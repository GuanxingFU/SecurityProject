import ssl
import socket
import logging
from idlelib.run import flush_stdout

import dns.resolver
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def parse_ech_config(ech_txt_record):
    return {"key": "parsed_public_key", "config": "parsed_ech_config"}


def fetch_ech_config(domain):
    try:
        # Try HTTPS record first
        https_response = dns.resolver.resolve(domain, "HTTPS")
        for record in https_response:
            ech_config = extract_ech_from_https(record)  # Custom extraction logic
            if ech_config:
                print("ECH Configuration Fetch sucess")
                return ech_config
    except Exception as e:
        logging.error(f"No HTTPS record, fallback to _echconfig: {e}")

    try:
        response = dns.resolver.resolve(f"_echconfig.{domain}", "TXT")
        for record in response:
            return parse_ech_config(record.to_text())
    except Exception as e:
        logging.error(f"Failed to fetch ECH configuration: {e}")
        return None


def extract_ech_from_https(record):
    """
    Extract ECH configuration from an HTTPS record.
    """
    try:
        # Parse the raw text output of the record
        raw_data = record.to_text()
        print("Raw Record Text:", raw_data)  # Debugging
        if 'ech="' in raw_data:
            # Extract the ECH value between quotes after `ech=`
            ech_config = raw_data.split('ech="')[-1].split('"')[0]
            return decode_ech(ech_config)
        else:
            return None
    except Exception as e:
        raise Exception(f"Failed to extract ECH configuration: {str(e)}")


def decode_ech(echconfig):
    """
    Decode ECH configuration (Base64 or binary format).
    """
    try:
        decoded = base64.b64decode(echconfig)
        return decoded  # Returns raw ECH config for now
    except Exception as e:
        raise Exception(f"Failed to decode ECH configuration: {str(e)}")

#connect->fetch->extract(DONE)->decode(DONE)->*fetch
def connect_with_ech():
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("server.crt")
        # context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)


        # Fetch and apply ECH configuration
        ech_config = fetch_ech_config(hostname)
        if ech_config:
            # context.ech_enable(ech_config)
            logging.info("Attempt to Connect -- ECH configuration applied.")

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                logging.info("ECH-enabled TLS handshake successful!")
                # cert = tls.getpeercert()
                # print("Peer Certificate:", cert)
                cert = tls.getpeercert()
                if cert:
                    # Extract the Common Name (CN) from the certificate
                    for subject in cert.get('subject', ()):
                        for key, value in subject:
                            if key == 'commonName':
                                print("Server Common Name:", value)

                    # Extract Subject Alternative Names (SANs) if available
                    san = cert.get('subjectAltName', ())
                    for name, value in san:
                        if name == 'DNS':
                            print("Subject Alternative Name:", value)
                return tls
    except ssl.SSLError as e:
        logging.error(f"ECH handshake failed: {e}")
        return None
    except socket.error as e:
        logging.error(f"Network error during ECH handshake: {e}")
        return None


def fallback_to_tls():
    try:
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # context.load_verify_locations("path/to/ca-bundle.crt")

        context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)


        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                logging.info("Fallback TLS handshake successful!")
                return tls
    except Exception as e:
        logging.error(f"Fallback TLS handshake failed: {e}")
        return None

# hostname = "ech-test.note.lat" #Decoy
# hostname = "blog.note.lat" #Actual
# hostname = "blog-forward.note.lat" #Actual
hostname = "blog-ech-inner.note.lat" #Actual

#TODO Fallback done by Client, how does browser knows the decoy server? Or just use it

# hostname = "example.com"
port = 443

# Attempt ECH handshake
tls_connection = connect_with_ech()
#TODO although there's no ech implementation, we get the ech config, and may used by other tool to send it
#TODO Server should reject non-ech?
if tls_connection is None:
    logging.info("Main -- Attempting fallback to standard TLS.")
    tls_connection = fallback_to_tls()

if tls_connection:
    logging.info("Handshake process completed.")

else:
    logging.error("All handshake attempts failed.")

# flush_stdout()
# logging.info("\n\n--------Fallback Testing--------")
# tls_connection = fallback_to_tls()
# if tls_connection:
#     logging.info("Handshake process completed.")
# else:
#     logging.error("Handshake attempts failed.")