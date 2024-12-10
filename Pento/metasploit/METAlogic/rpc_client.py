from pymetasploit3.msfrpc import MsfRpcClient

def get_client():
    try:
        # Use the credentials from your MSF output
        client = MsfRpcClient('yourpassword', username='msf', port=55552)
        return client
    except Exception as e:
        raise Exception(f"Failed to connect to Metasploit RPC: {e}")
