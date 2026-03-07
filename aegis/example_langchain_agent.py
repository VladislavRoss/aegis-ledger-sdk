"""
example_langchain_agent.py — Full working example of a LangChain ReAct
agent with Aegis tamperproof tracing.

This demonstrates the "2-line integration" promise:
  1. Import AegisCallbackHandler
  2. Pass it to your agent's callbacks

Every tool call, LLM decision, and error is automatically logged to an
immutable, cryptographically verifiable ledger on the Internet Computer.

Setup:
    pip install aegis-ledger-sdk[langchain] langchain-openai langchain-community
    aegis keygen ./agent_key.pem
    # Register the public key at https://www.aegis-ledger.com/dashboard
"""

# ── Aegis: Line 1 of 2 ─────────────────────────────────────────────
from aegis import AegisClient
from aegis.langchain import AegisCallbackHandler
from langchain.agents import AgentExecutor, create_react_agent
from langchain_community.tools import DuckDuckGoSearchResults
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

client = AegisClient(
    canister_id="toqqq-lqaaa-aaaae-afc2a-cai",  # Your canister ID
    api_key_id="ak_3f8a9b2c1d4e5f60",            # From Aegis dashboard
    private_key_path="./agent_key.pem",            # Generated via: aegis keygen
    agent_id="agent_research_v1",
)
handler = AegisCallbackHandler(client)
# ── Aegis: Line 2 of 2 ─────────────────────────────────────────────

# Standard LangChain agent setup (nothing Aegis-specific below)
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
tools = [DuckDuckGoSearchResults(max_results=3)]

template = """Answer the following question using the tools available.

You have access to the following tools:
{tools}

Use the following format:
Question: the input question
Thought: what you need to do
Action: the action to take, one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (repeat Thought/Action/Observation as needed)
Thought: I now know the final answer
Final Answer: the final answer

Question: {input}
{agent_scratchpad}"""

prompt = PromptTemplate.from_template(template)
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# Run the agent — Aegis logs everything automatically via the callback
result = executor.invoke(
    {"input": "What are the latest developments in EU AI regulation?"},
    config={"callbacks": [handler]},  # ← This is the only Aegis-specific line
)

print(f"\nAnswer: {result['output']}")
print(f"\nAegis: {client.sequence_number} actions logged to session {client.session_id}")
print(f"View trace: https://www.aegis-ledger.com/trace/{client.session_id}")
