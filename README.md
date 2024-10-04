In this project we have created a tool allowing communication between two machines
connected by Internet via a "hidden channel", that is to say invisible to monitoring tools that can intercept the IP packets used for this communication. We are faced with many constraints
to achieve this goal, including:
— Encapsulation of these packets in a protocol to act as a normal communication
— ​​Protect these packets by encryption so that in case of interception, the packets are inaccessible
— Have the possibility of intercepting these packets on the network (since they will be hidden)
— Extract these hidden packets
— Be able to use socat between interlocutors to establish or wait for an exchange based on TCP or
UDP
