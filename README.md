# Crypted Chat
Simple encrypted chat

# Usage:
  CryptedChat -s(--server) <ip> => Start crypted chat at server mode at default port: 8888
  CryptedChat -s(--server) <ip>:<port> => Start crypted chat at server mode at custom port
  CryptedChat -c(--client) <ip> => Connect to crypted chat at default port: 8888
  CryptedChat -c(--client) <ip>:<port> => Connect to crypted chat at custom port
  
# Available commands:
  /stop - exit from chat(Completion of the program from both sides)
  /recv_<filename> - receives data and writes it to a file from another user
  /send_<filename> - sends file to another user
