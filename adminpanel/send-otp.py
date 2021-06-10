import telnyx
telnyx.api_key = "KEY0179F531AF3BB551376A921623235245_E9m3eGUsHbns1W0Juxoi24"

telnyx.Message.create(
  from_="+15736058855", # Your Telnyx number
  to="+917678689353",
  text="This is a message from BRASI and message is Hello, World!"
)