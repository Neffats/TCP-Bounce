BLOCK_SZ = 3
CHAR_MASKS = [0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF]
INIT_MASKS = {'MSG_LEN': 0x0FFF0000, 'PORT': 0x0000FFFF}
CONTROL_HEADERS = {'DATA': 1, 'END': 15}
TYPE_CODES = {0x01:'BLOCK'}


BLOCK_TYPE = 1