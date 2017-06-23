import re
username_reg= "^[a-zA-Z0-9_-]{3,20}$"
password_reg= "^.{3,20}$"

def valid_field(text, field_type):
    if text:
        if field_type=='username':
            return re.compile("^[a-zA-Z0-9_-]{3,20}$").match(text)
        if field_type=='password':
            return re.compile("^.{3,20}$").match(text)
    return False
