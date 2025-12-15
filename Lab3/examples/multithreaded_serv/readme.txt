The TCP client sends a number, entered as a command line input by the user, to the server.

The server computes the sum of all positive integers up to that entered number.

The test_script.sh file sends multiple client requests in succession simulating heavy traffic.

The two server codes implement multi-threaded server using different approaches.

One uses the "one-thread-per-request" model and the other uses the "thread pool" model.