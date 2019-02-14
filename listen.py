import tcpbounce

l = tcpbounce.Listener(15424, 'tcp')

l.listen()

l.print_message()