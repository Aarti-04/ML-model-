# import socketio
# import eventlet.wsgi

# # create a Socket.IO server
# sio = socketio.Server(cors_allowed_origins='*')

# # wrap with a WSGI application
# app = socketio.WSGIApp(sio)

# @sio.event
# def connect(sid, environ):
#     print('Client connected:', sid)


# # start the server and listen for connections
# if __name__ == '__main__':
#     eventlet.wsgi.server(eventlet.listen(('0.0.0.0', 8080)), app)