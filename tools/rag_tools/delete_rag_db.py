__import__('pysqlite3')
import sys
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

from pymilvus import MilvusClient
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

def delete_milvus_collection(collection_name):
    """Delete a Milvus collection."""
    logger.info(f"Deleting Milvus collection: {collection_name}")
    client = MilvusClient(
        uri="http://localhost:19530",
        token="root:Milvus"
    )
    client.drop_collection(collection_name=collection_name)
    logger.info(f"Collection '{collection_name}' deleted successfully.")

if __name__ == "__main__":
    collection_name = "rag_collection_demo_1"
    delete_milvus_collection(collection_name)