from random import randint
from .models import Otp
import telnyx


telnyx.api_key = "KEY0179F531AF3BB551376A921623235245_E9m3eGUsHbns1W0Juxoi24"


def send_otp(country_code, number):
    print(country_code, number)
    print('form send otp')
    otp = randint(100000, 999999)
    print(otp)
    Otp.objects.create(number=number, otp=otp)
    telnyx.Message.create(
        from_="+15736058855",  # Your Telnyx number
        to='+' + str(int(country_code)) + str(number),
        text=f'Your one time password from BRASI is {otp}. This otp is valid for next 60 seconds.'
    )
