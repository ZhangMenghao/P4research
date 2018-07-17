import BaseHTTPServer
import time

counter = 0
start_time = time.time()
Page = "axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba axibaaxibaaxibaaxiba "

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    global Page
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(Page)))
        self.end_headers()
        self.wfile.write(Page)
        global counter
        global start_time
        counter += 1
        print counter, ' at ', time.time() - start_time, ' sent!'
if __name__ == '__main__':
    serverAddress = ('', 8080)
    server = BaseHTTPServer.HTTPServer(serverAddress, RequestHandler)
    server.serve_forever()
