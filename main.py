from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from datetime import datetime
from dotenv import load_dotenv
from tools import list_iam_users_with_permissions, get_iam_user_permissions, save_to_file, search_duckduckgo, modify_iam_resource
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.exceptions import OutputParserException
from langchain_classic.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.chat_history import InMemoryChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from prompt_toolkit import prompt
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import FormattedText
from shutil import get_terminal_size


class ResearchOutputParser(BaseModel):
    topic: str
    summary: str
    list_of_users: list[str]


def get_prompt():
    width = get_terminal_size().columns
    sep = "─" * width
    return FormattedText([
        ("class:separator", sep + "\n"),
        ("class:prompt", " > "),
    ])


def prompt_toolbar():
    return FormattedText([
        ("class:bottom-toolbar", " Type "),
        ("class:bottom-toolbar-key", "/q"),
        ("class:bottom-toolbar", " to quit"),
    ])


if __name__ == "__main__":

    output_parser = PydanticOutputParser(pydantic_object=ResearchOutputParser)

    load_dotenv()

    llm = ChatOpenAI(model="gpt-4o-mini")
    # llm = ChatOllama(model="qwen2:1.5b")

    chat_prompt = ChatPromptTemplate.from_messages([
        ("system", (
            "You are a personal AWS IAM security assistant. "
            "Your role is to help evaluate and review permissions assigned to AWS IAM users. "
            "You have access to tools that can retrieve IAM user data directly from AWS. "
            "\n\n"
            "When evaluating permissions, always consider the principle of least privilege: "
            "users should have only the permissions necessary to perform their job. "
            "Flag any of the following as potential security risks:\n"
            "- Overly broad permissions such as '*' actions or '*' resources\n"
            "- Administrative or root-level access granted to regular users\n"
            "- Unused or outdated permissions that should be revoked\n"
            "- Sensitive service access (IAM, S3, EC2, billing) without clear justification\n"
            "\n"
            "When asked about a specific user, use the get_iam_user_permissions tool. "
            "When asked for an overview of all users, use the list_iam_users_with_permissions tool. "
            "Always provide a clear, concise assessment with actionable recommendations."
            "\n\n"
            "{format_instructions}"
        )),
        ("placeholder", "{chat_history}"),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ]).partial(format_instructions=output_parser.get_format_instructions())

    agent_tools = [
        list_iam_users_with_permissions,
        get_iam_user_permissions,
        save_to_file,
        search_duckduckgo,
        modify_iam_resource,
    ]

    agent = create_tool_calling_agent(llm=llm, prompt=chat_prompt, tools=agent_tools)
    agent_executor = AgentExecutor(agent=agent, tools=agent_tools, verbose=True)

    # In-memory store: session_id -> ChatMessageHistory
    store = {}

    def get_session_history(session_id: str) -> InMemoryChatMessageHistory:
        if session_id not in store:
            store[session_id] = InMemoryChatMessageHistory()
        return store[session_id]

    # Wraps agent_executor — history is injected and saved automatically
    agent_with_history = RunnableWithMessageHistory(
        agent_executor,
        get_session_history,
        input_messages_key="input",
        history_messages_key="chat_history",
    )

    style = Style.from_dict({
        "separator": "#555555",
        "prompt": "#ffffff bold",
        "bottom-toolbar": "noreverse bg:#222222 #888888",
        "bottom-toolbar-key": "noreverse bg:#222222 #ffffff bold",
    })

    while (user_query := prompt(get_prompt, style=style, bottom_toolbar=prompt_toolbar)) != "/q":
        raw_output = agent_with_history.invoke(
            {"input": user_query},
            config={"configurable": {"session_id": "main"}},
        )

        try:
            parsed_output = output_parser.parse(raw_output["output"])
            print(f"\n--- TOPIC ---\n{parsed_output.topic}")
            print(f"\n--- SUMMARY ---\n{parsed_output.summary}")
            print(f"\n--- Affected Users: ---\n{parsed_output.list_of_users}")
        except OutputParserException:
            # Agent replied with plain text (e.g. greeting), not structured JSON
            print(f"\n{raw_output['output']}")

    print("Thanks!! See you")
