from utils.vectorizor import upsertDocToIndex, upsertTextToIndex, get_answer
from langchain.text_splitter import CharacterTextSplitter
from langchain.prompts import PromptTemplate

def generate_kb_from_document(chunks, unique_id, doc_index, _type):
    try:
        upsertDocToIndex("knowledge-base", unique_id, doc_index, chunks, _type)
    except Exception as e:
        print("Generating the knoledgebase >>>" ,str(e))
        return - 1

def generate_kb_from_url(chunks, unique_id, doc_index, _type):
    try:
        upsertTextToIndex("knowledge-base", unique_id, doc_index, chunks, _type)
    except Exception as e:
        print("Generating the knoledgebase >>>" ,str(e))
        return - 1

def tiktoken_doc_split(text):
    text_splitter = CharacterTextSplitter(
                separator = "\n", chunk_size=1200, chunk_overlap=200, length_function = len,
            )
    chunks = text_splitter.split_documents(text)
    print("Chunks length >>>>", len(chunks))
    return chunks

def tiktoken_text_split(text):
    text_splitter = CharacterTextSplitter(
                separator = "\n", chunk_size=1200, chunk_overlap=200, length_function = len,
            )
    chunks = text_splitter.split_text(text)
    print("Chunks length >>>>", len(chunks))
    return chunks

def generate(bot_id, session_id, query, knowledge_base, lang):
    

    result = get_answer(bot_id, session_id, query, knowledge_base, lang)

    return result
  