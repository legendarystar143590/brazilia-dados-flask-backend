
import openai
from pinecone import Pinecone, ServerlessSpec
# from openai import OpenAI
import time
from uuid import uuid4
# from langchain.vectorstores import Pinecone
from langchain_openai import OpenAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains.question_answering import load_qa_chain
from langchain.memory import ConversationBufferMemory
from langchain.chains import RetrievalQA
from langdetect import detect
from pinecone import Pinecone, ServerlessSpec
# from langchain.sql_database import SQLDatabase
from models import Conversation, Bot
# from langchain import LargeLanguageModel
import os
import base64
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.getenv("PINECONE_ENVIRONMENT")
PINECONE_INDEX_DIMENSION = int(os.getenv("PINECONE_INDEX_DIMENSION", "3072"))
PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX_NAME")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL")

print(PINECONE_API_KEY)
print(PINECONE_ENVIRONMENT)
pc = Pinecone(api_key=PINECONE_API_KEY)

#  Delete an index with name
def deleteIndex():
    try:
        for index_name in pc.list_indexes().names():
            pc.delete_index(index_name)
        else:
            print("There is no such an index to l")
    except Exception as e:
        print("Error in deleteIndex()", str(e))
        pass

# Upsert Doc into index with 
def upsertDocToIndex(index_name, collection_name, doc_index, chunks, _type):
    try:
        
        embeddings = OpenAIEmbeddings(openai_api_key=OPENAI_API_KEY, model=EMBEDDING_MODEL)
        vectors = []
        count = 0
        batch_size = 100
        p_index = pc.Index(index_name)
        for chunk in chunks:
            chunk.metadata['collection_name'] = collection_name
            chunk.metadata['doc_index'] = doc_index
            chunk.metadata['type'] = _type
            chunk.metadata['text'] = chunk.page_content
            metadata = {"collection_name": collection_name, "doc_index": doc_index, "type":_type, "text":chunk.page_content}
            
            s_vector = {}
            s_vector['id'] = str(doc_index+count)
            s_vector['values'] = embeddings.embed_query(chunk.page_content)
            s_vector['metadata'] = metadata
            vectors.append(s_vector)
            if len(vectors) % batch_size == 0:
                p_index.upsert(vectors=vectors)
                vectors = []
            
            count += 1
        if vectors:
            p_index.upsert(vectors=vectors)

    except Exception as e:
        print("Error in upsertDataToIndex()", str(e))
        pass

# Upsert Text into index with 
def upsertTextToIndex(index_name, collection_name, doc_index, chunks, _type):
    try:
        embeddings = OpenAIEmbeddings(openai_api_key=OPENAI_API_KEY, model=EMBEDDING_MODEL)
        vectors = []
        count = 0
        for chunk in chunks:
            count = count + 1
            metadata = {"collection_name": collection_name, "doc_index": doc_index, "type":_type, "text": chunk}
            
            s_vector = {}
            s_vector['id'] = str(doc_index+count)
            s_vector['values'] = embeddings.embed_query(chunk)
            s_vector['metadata'] = metadata

            vectors.append(s_vector)

        p_index = pc.Index(index_name)
        p_index.upsert(vectors=vectors)
    except Exception as e:
        print("Error in upsertDataToIndex()", str(e))
        pass

def upsertProductsToIndex(index_name, collection_name, doc_index, chunks, _type):
    try:
        print("Upserting products to index")
        embeddings = OpenAIEmbeddings(openai_api_key=OPENAI_API_KEY, model=EMBEDDING_MODEL)
        vectors = []
        count = 0
        for chunk in chunks:
            count = count + 1
            metadata = {"collection_name": collection_name, "doc_index": doc_index, "type":_type, "text": chunk}
            
            s_vector = {}
            s_vector['id'] = str(doc_index+count)
            print(s_vector['id'])
            s_vector['values'] = embeddings.embed_query(chunk)
            s_vector['metadata'] = metadata

            vectors.append(s_vector)

        p_index = pc.Index(index_name)
        p_index.upsert(vectors=vectors)
    except Exception as e:
        print("Error in upsertDataToIndex()", str(e))
        pass

# Delete doc in the vector database
def delDocument(collection_name, doc_index, _type):
    index = pc.Index("knowledge-base")
    # filter_con = {"collection_name": collection_name, "doc_index": str(doc_index), "type":_type}
    filter_con = { "collection_name": collection_name, "doc_index": doc_index, "type":_type}
    try:
        print(filter_con)
        index.delete(filter=filter_con)
        return True
    except Exception as e:
        print(str(e))
        return False

# Delete knowledge base in the vector database
def delKnowledgeBase(collection_name):
    index = pc.Index("knowledge-base")
    # filter_con = {"collection_name": collection_name, "doc_index": str(doc_index), "type":_type}
    filter_con = { "collection_name": collection_name}
    try:
        print(filter_con)
        index.delete(filter=filter_con)
        return True
    except Exception as e:
        print(str(e))
        return False

def detect_language(text):
    try:
        return detect(text)
    except:
        return 'en'  # default to English if detection fails

#  Generate the response
def get_answer(bot_id, session_id, query, knowledge_base, website):
    try:
        bot = Bot.get_by_id(bot_id)
        query_language = detect_language(query)
        print(query_language)

        # Get products from the database
        print(website)
        
        starter = f"""
        Q:
        Please follow these guidelines when responding:
        1. Always reply in the language of the human_input if {query_language}'s not English.
        2. Determine if the user's query is technical or general.
        3. For technical queries:
        - Summarize the context and provide relevant information if available.
        - If the context lacks relevant information, respond with the translated text: "Sorry, I can't help with that. Do you want to book a ticket? If so, leave me your email."
        4. For non-technical queries:
        - Do not use context information.
        - Respond general information. Here is some general information: You are a helpful assistant named {bot.name}. Always respond politely and use conversational language. Consider the meaning of the user's query and follow these guidelines.
        5. Always check the context before determining your response and adhere strictly to these guidelines.
        6. Your name is {bot.name}. Remember this throughout the conversation, and if asked, state your name.

        Note: Ensure that all responses, including the translated default message, are in the language of the human_input.
        human_input:{query}

        """
        template = """"""
        end = """
        Context:{context}
        Chat history: {chat_history}
        Human: {human_input}
        A: """
        template =starter + end
        # print(template)
        
        prompt = PromptTemplate(
            input_variables=["chat_history", "human_input"],
            template=template
        )
        embeddings = OpenAIEmbeddings(openai_api_key=OPENAI_API_KEY, model=EMBEDDING_MODEL)
        # print(embeddings)
        docsearch = PineconeVectorStore.from_existing_index(
                index_name='knowledge-base', embedding=embeddings)
        
        docs = []
        if knowledge_base !="-1":        
            condition = {"collection_name": knowledge_base}
            print(condition)

            docs = docsearch.similarity_search(query, k=3, filter=condition)
            print("Got here1  >>>", docs)

        llm = ChatOpenAI(temperature=0.7, model="gpt-3.5-turbo-0125", openai_api_key=OPENAI_API_KEY, streaming=True)
        memory = ConversationBufferMemory(memory_key="chat_history", input_key="human_input")
        stuff_chain = load_qa_chain(llm, chain_type="stuff", prompt=prompt, memory=memory)
        latest_chat_history = Conversation.get_latest_by_session(session_id)
        # print(docs)
        reduce_chat_history = ""
        for index, record in enumerate(latest_chat_history):
            if index < 4:
                # print(record.response)
                stuff_chain.memory.save_context({'human_input': record.user_message}, {'output': record.response})
                reduce_chat_history += f"Human: {record.user_message}\nBot: {record.response}\n"
                # reduce_chain.memory.save_context({'human_input': record.user_message}, {'output': record.response})
            else:
                record.delete()
        output = stuff_chain.invoke({"input_documents": docs, "human_input": query}, return_only_outputs=False)
        new_conv = Conversation(query, output["output_text"], bot_id, session_id)
        new_conv.save()
        return output["output_text"]
    except Exception as e:
        print(str(e))
        return "Network error"
    