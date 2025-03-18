__import__('pysqlite3')
import sys
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import ollama
from pymilvus import MilvusClient, connections, FieldSchema, CollectionSchema, DataType, Collection, utility
import os
import pickle
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

def create_milvus_collection(collection_name):
    """Create a Milvus collection for storing document embeddings."""
    logger.info("Initializing Milvus client.")
    connections.connect("default", host="localhost", port="19530")

    fields = [
        FieldSchema(name="id", dtype=DataType.VARCHAR, is_primary=True, max_length=100),
        FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=1024),
        FieldSchema(name="document", dtype=DataType.VARCHAR, max_length=65535)
    ]
    schema = CollectionSchema(fields, description="A collection for RAG")

    if utility.has_collection(collection_name):
        logger.info(f"Collection '{collection_name}' already exists. Retrieving it.")
        collection = Collection(collection_name)
    else:
        logger.info(f"Creating new Milvus collection: {collection_name}")
        collection = Collection(collection_name, schema)

    if not collection.has_index():
        logger.info("Creating index on the 'embedding' field.")
        index_params = {
            "index_type": "IVF_FLAT",
            "metric_type": "IP",
            "params": {"nlist": 128}
        }
        collection.create_index(field_name="embedding", index_params=index_params)
        logger.info("Index created successfully.")

    logger.info(f"Collection '{collection_name}' is ready.")
    return collection

def add_documents_to_collection(collection, documents, ids, embedding_model):
    """Add documents to the Milvus collection."""
    logger.info(f"Adding {len(documents)} documents to the collection.")
    
    embeddings = []
    for doc in documents:
        response = ollama.embeddings(model=embedding_model, prompt=doc)
        embeddings.append(response["embedding"])
    
    entities = [ids, embeddings, documents]
    collection.insert(entities)
    logger.info("Documents added successfully.")

def load_documents_from_pickle(file_path):
    """Load documents from a pickle file."""
    logger.info(f"Loading documents from pickle file: {file_path}")
    with open(file_path, 'rb') as f:
        docs = pickle.load(f)
    logger.info(f"Loaded {len(docs)} documents.")
    return docs

def preprocess_documents(docs):
    """Preprocess documents by removing newline characters."""
    logger.info("Preprocessing documents to remove newline characters.")
    preprocessed_docs = {doc_id: doc.replace("\n", " ") for doc_id, doc in docs.items()}
    logger.info("Newline characters removed from documents.")
    return preprocessed_docs

if __name__ == "__main__":
    model_name = "llama3.1:8b"
    embedding_model = "mxbai-embed-large:335m"
    collection_name = "rag_collection_demo_1"

    collection = create_milvus_collection(collection_name)

    docs = load_documents_from_pickle('../dataset/new_cwe_explanations_for_rag.pkl')
    preprocessed_docs = preprocess_documents(docs)
    add_documents_to_collection(collection, list(preprocessed_docs.values()), list(preprocessed_docs.keys()), embedding_model)