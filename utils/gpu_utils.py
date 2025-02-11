import gc
import logging
import time


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def free_gpu_memory():
    gc.collect()

def pause_if_needed(start_time, pause_interval=1200, pause_duration=180):
    """Pauses execution every `pause_interval` seconds for `pause_duration` seconds."""
    elapsed_time = time.perf_counter() - start_time
    if elapsed_time >= pause_interval:
        logger.info("Pausing for 3 minutes to cool down the GPU...")
        free_gpu_memory()
        time.sleep(pause_duration)
        logger.info("Resuming execution...")
        return time.perf_counter()  # Reset the timer after pausing
    return start_time  # Return the original start_time if no pause happens

def sleep_for_minutes(minutes):
  """Sleeps for the specified number of minutes."""
  free_gpu_memory()
  seconds = minutes * 60
  logger.info(f"Sleeping for {minutes} minutes...")
  time.sleep(seconds)
  logger.info("Woke up from sleep.")