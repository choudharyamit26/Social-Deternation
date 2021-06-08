import telnyx
telnyx.api_key = "DQpYpPN/nb9oRbkosjq4WsuVwHZ4/3j/Ob1LepeLSfk="

telnyx.Message.create(
  from_="+18665552368", # Your Telnyx number
  to="+917678689353",
  text="Hello, World!"
)