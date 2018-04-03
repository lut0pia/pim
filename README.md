# pim

## Goals

- Allow people to communicate securely and without relying on big businesses.
- Be accessible to anyone from the browser, no installation required.
- Store any information locally, share it directly and only with your friends, never giving it to a server.
- By the people, for the people (cheesy I know).

## State

This project is in a very early stage, most things can and *will* change, some may break and you may lose data (pim-related, e.g. conversations). It's not ready for simple casual use, but if you're willing to try things and maybe contribute, hop on!
If you want to test the program in its current state, there is a server setup at [pim.luciencatonnet.com](https://pim.luciencatonnet.com).

## How it works

### Signup (automatic)

You first have to generate a public/private key pair to create an account. That's done automatically for you if you have no account yet. The public key will be what you share to add friends, it's really like a phone number.

### Public key exchange

Because it's like a phone number, your friend has to know it to call you, or you have to know theirs to call them. The pim protocol is secure for communication, but it does not handle that first exchange of key: you have to use a secondary medium to communicate first. It's alright though, because a public key can only be used to contact you, not impersonate you.

### Authentification (automatic)

When starting a pim session, you'll connect with multiple servers. You will then authenticate, by proving that you know the private key to your public key. Once the servers know who you are, they'll be able to relay messages to you (those are not the chat messages).

### Signaling (automatic)

You can now start the connection process by asking the servers to relay messages between you and your friend. You don't actually trust the servers though, you sign your messages, and you verify the ones you receive. In the worst case scenario, no server does what you want (they're all corrupt or buggy) and you can't connect. There is no possibility of man-in-the-middle'ing your conversation. Once you are connected to someone, you are guaranteed that they are the owner of the public key (because they signed their messages with their key), and that nobody is listening to your conversation.

### Conversation

That's it! You can now converse like in any other chat system!

## Dependencies

### Server

- NodeJS
- Forge
- WebSocket

### Client

- Forge
- WebSocket
- WebRTC
