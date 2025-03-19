from langchain_ollama import OllamaLLM
from time import sleep
from httpx import RemoteProtocolError
from langchain_core.prompts import ChatPromptTemplate
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from server.rag import PermissionRAG


def setup_model():
    """
    Sets up and configures a language model chain for text processing.

    Returns:
        Chain: A configured chain combining the prompt template and language model,
              ready for text generation/processing.
    """

    with open('./server/prompt_template.txt', 'r') as file:
        template = file.read()

    callback_man = CallbackManager([StreamingStdOutCallbackHandler()])
    model = OllamaLLM(model="llama3.2:1b",
                      callback_manager=callback_man, temperature=0.4, num_ctx=2048, num_thread=8)
    prompt = ChatPromptTemplate.from_template(template)
    chain = prompt | model
    return chain


def init_RAG():
    """
    Initializes and returns a PermissionRAG instance for permission analysis.

    Returns:
        PermissionRAG: A new instance of the PermissionRAG class initialized with
                       the permissions dataset.
    """
    return PermissionRAG('./server/permissions_dataset.json')


def handle_explanations(chain, permissions, num_permissions, max_retries=3):
    """
    Processes a list of permissions through a language model chain with retry mechanism.

    Args:
        chain: The language model chain used for processing permissions
        permissions (list): List of permission dictionaries containing permission details
        num_permissions (int): Number of permissions to process
        max_retries (int, optional): Maximum number of retry attempts. Defaults to 3.

    Returns:
        list: List of processed results from the language model chain for each permission
    """
    print("\nStep 1: Getting relevant context from database...\n")
    permRAG = init_RAG()
    result = []
    print("\nStep 2: Analyzing permissions with context...\n")
    for attempt in range(max_retries):
        try:
            for permission in permissions:
                permission_context = permRAG.get_relevant_context(permission)
                tmp = chain.invoke({
                    "permission": permission['permission'],
                    "context": permission_context
                })
                result.append(tmp)
                print("\n")
            return result
        except RemoteProtocolError as e:
            if attempt == max_retries - 1:
                raise Exception(
                    f"Failed after {max_retries} attempts: {str(e)}")
            print(f"Attempt {attempt + 1} failed. Retrying in 2 seconds...")
            sleep(2)
