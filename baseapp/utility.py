import re 
from rest_framework.exceptions import ValidationError

email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
phone_regex = re.compile(r"^(?:\+998[\s-]?)?(?:\d{2}|[378]{2}|9[0-9])[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}$")
username_regex = re.compile(r"^[a-zA-Z0-9_]{6,16}$")


def email_or_phone(email_phone_number):
    if re.fullmatch(email_regex, email_phone_number):
        data='email'
    elif re.fullmatch(phone_regex, email_phone_number):
        data='phone'
        
    else:
        data={
            'success': 'False',
            'message': 'siz telefon raqam yoki emailni notogri kiritdingiz'
                
        }  
        
        raise ValidationError(data)
    
    return data


def check_userinputtype(userinput):
    if re.fullmatch(email_regex, userinput):
        data='email'
    elif re.fullmatch(phone_regex, userinput):
        data='phone'
        
    elif re.fullmatch(username_regex, userinput):
        data='username'
        
        
    else:
        data={
            'messsage': 'False',
            'success': 'Telefon raqam , email, username xato kiritilgan bulishi mumkin'
        }
        
        raise ValidationError(data)
    
    return data
        
    
    
    


