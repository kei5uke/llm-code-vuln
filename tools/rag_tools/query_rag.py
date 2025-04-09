__import__('pysqlite3')
import sys
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import ollama
from pymilvus import Collection, connections  # Import connections
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("rag_pipeline.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def initialize_milvus_connection():
    """Initialize the Milvus connection."""
    logger.info("Initializing Milvus connection.")
    connections.connect("default", host="localhost", port="19530")
    logger.info("Milvus connection established.")

def query_milvus(collection, query_text, embedding_model, n_results=3):
    """Query the Milvus collection for relevant documents."""
    logger.info(f"Querying Milvus collection with query: {query_text}")
    collection.load()
    
    if not collection.has_index():
        logger.error("Index not found. Please create an index on the 'embedding' field.")
        raise Exception("Index not found. Create an index before querying.")
    
    response = ollama.embeddings(model=embedding_model, prompt=query_text)
    query_embedding = response["embedding"]
    logger.debug(f"Query Embedding: {query_embedding}")
    
    search_params = {
        "metric_type": "IP",
        "params": {}
    }
    
    results = collection.search(
        data=[query_embedding],
        anns_field="embedding",
        param=search_params,
        limit=n_results,
        output_fields=["document"]
    )
    
    retrieved_docs = [hit.entity.get("document") for hit in results[0]]
    logger.info(f"Retrieved {len(retrieved_docs)} results.")

    retrieved_docs = "\n".join(retrieved_docs)

    return retrieved_docs

def rag_pipeline(collection, model_name, embedding_model, query_text):
    """Perform Retrieval-Augmented Generation (RAG) by combining Milvus and Ollama."""
    logger.info("Starting RAG pipeline.")
    retrieved_docs = query_milvus(collection, query_text, embedding_model)
    
    if retrieved_docs:
        context = retrieved_docs
        logger.info(f"Retrieved context: {context}")
    else:
        context = "No relevant documents found."
        logger.warning("No relevant documents found for the query.")

    augmented_prompt = f"Context: {context}\nQuestion: {query_text}\nAnswer:"
    logger.info("Augmented prompt created.")
    # logger.info(f"Augmented prompt: {augmented_prompt}")

    response = ollama.generate(model=model_name, prompt=augmented_prompt)
    logger.info("RAG pipeline completed.")
    return response["response"]

if __name__ == "__main__":
    model_name = "llama3.1:8b"
    embedding_model = "mxbai-embed-large:335m"
    collection_name = "rag_collection_demo_1"

    # Initialize Milvus connection
    initialize_milvus_connection()

    # Load the collection
    collection = Collection(collection_name)

    # Example query
    query_text = """What is CWE related to SQL Injection?"""
    query_text = """What is the CWE ID for SQL Injection vulnerabilities, and can you provide a description?"""
    query_text = """What is the CWE ID for the vulnerability where an attacker can manipulate SQL queries by injecting malicious input into user-controllable inputs, leading to unauthorized access to databases, data leakage, or data corruption? This vulnerability often occurs when user input is not properly sanitized or parameterized before being used in SQL commands."""
    logger.info(f"Running example query: {query_text}")
    response = rag_pipeline(collection, model_name, embedding_model, query_text)
    logger.info("######## Response ########")
    logger.info(response)