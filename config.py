import os

mitm_port = "8080"
enable_player = True

wireshark_file_name = "wireshark.json"
tshark_file_name = "tshark.json"
player_file_name = "media-internals.txt"
request_file_name = "request.json"
response_file_name = "response.json"

# Comparison section
is_comparision = True
second_wireshark_file_name = "wireshark2.json"
second_tshark_file_name = "tshark2.json"
second_player_file_name = "media-internals2.txt"
second_mitm_request_file_name = "request2.json"
second_mitm_response_file_name = "response2.json"

# Function for return values
def get_mitm_port():
    return mitm_port

def get_wireshark_file_name():
    return wireshark_file_name

def get_tshark_file_name():
    return tshark_file_name

def get_player_file_name():
    return player_file_name

def get_request_file_name():
    return request_file_name

def get_response_file_name():
    return response_file_name

# Comparison section
def get_is_comparision():
    return is_comparision

def get_second_wireshark_file_name():
    return second_wireshark_file_name

def get_second_tshark_file_name():
    return second_tshark_file_name

def get_second_player_file_name():
    return second_player_file_name

def get_second_mitm_request_file_name():
    return second_mitm_request_file_name

def get_second_mitm_response_file_name():
    return second_mitm_response_file_name

def get_enable_player():
    return enable_player


def is_file_exist(file_name):
    if os.path.exists(file_name):
        return True
    else:
        print("File Error: %s is not in %s directory."%(file_name, str(os.getcwd())))
        exit()
