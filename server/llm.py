from langchain_ollama import OllamaLLM
from time import sleep
from httpx import RemoteProtocolError
from langchain_core.prompts import ChatPromptTemplate
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import (
    StreamingStdOutCallbackHandler,
)


# ----------------------------- Model set up ----------------------------- #
def setup_model():

    with open('./server/prompt_template.txt', 'r') as file:
        template = file.read()

    callback_man = CallbackManager([StreamingStdOutCallbackHandler()])
    model = OllamaLLM(model="llama3.2",
                      callback_manager=callback_man, temperature=0.4, num_ctx=1024)
    prompt = ChatPromptTemplate.from_template(template)
    chain = prompt | model
    return chain


def handle_explanations(chain, permissions, num_permissions, max_retries=3):
    

    print("\nStep 1: Explaining permissions...\n")
    for attempt in range(max_retries):
        try:
            result = chain.invoke({"permissions_list": permissions, "number_of_permissions": num_permissions})
            return result
        except RemoteProtocolError as e:
            if attempt == max_retries - 1:
                raise Exception(f"Failed after {max_retries} attempts: {str(e)}")
            print(f"Attempt {attempt + 1} failed. Retrying in 2 seconds...")
            sleep(2)
