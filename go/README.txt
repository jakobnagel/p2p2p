To run the code, first build the executables:
cd go
make all

Then you can find the executables:
go/bin/client
go/bin/server

Start the server
./go/bin/server --password <your password>

Use the client to find services on your network
./go/bin/client get-services

Use the client to list/get files
./go/bin/client --password <pass> --host <host from get-services> list-files
./go/bin/client --password <pass> --host <host from get-services> get-file <filename>
./go/bin/client --password <pass> --host <host from get-services> send-file <filename>

