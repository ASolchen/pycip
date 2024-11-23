import logging
from adapter import Adapter

def main():
    # Configure logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        # Initialize and start the Adapter
        adapter = Adapter(host='0.0.0.0', tcp_port=44818, udp_port=2222)
        adapter.start_server()
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        adapter.close()

if __name__ == "__main__":
    main()