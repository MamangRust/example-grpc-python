import grpc
from concurrent import futures
import todo_pb2
import todo_pb2_grpc
from jose import JWTError, jwt
from grpc import StatusCode
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# JWT configurations
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

class AuthInterceptor(grpc.ServerInterceptor):
    def __init__(self):
        self._secret_key = SECRET_KEY
        self._algorithm = ALGORITHM

    def authenticate(self, metadata):
        """Extract and verify JWT token from metadata"""
        auth_header = None
        for key, value in metadata:
            if key.lower() == "authorization":
                auth_header = value
                break
                
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
            
        try:
            token = auth_header.split("Bearer ")[1]
            payload = jwt.decode(token, self._secret_key, algorithms=[self._algorithm])
            return payload
        except JWTError as e:
            logging.error(f"JWT verification failed: {str(e)}")
            return None

    def intercept_service(self, continuation, handler_call_details):
        metadata = handler_call_details.invocation_metadata
        auth_result = self.authenticate(metadata)
        
        if not auth_result:
            return self._unauthenticated_rpc
            
        return continuation(handler_call_details)

    def _unauthenticated_rpc(self, request, context):
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing authentication token")

class TodoService(todo_pb2_grpc.TodoServiceServicer):
    def __init__(self):
        self.todos = []

    def AddTodo(self, request, context):
        try:
            todo = todo_pb2.TodoItem(
                id=request.id,
                title=request.title,
                description=request.description
            )
            self.todos.append(todo)
            logging.info(f"Added todo with ID: {request.id}")
            return todo_pb2.TodoResponse(message="Todo added successfully")
        except Exception as e:
            logging.error(f"Error adding todo: {str(e)}")
            context.abort(grpc.StatusCode.INTERNAL, f"Error adding todo: {str(e)}")

    def GetTodos(self, request, context):
        try:
            logging.info(f"Retrieving {len(self.todos)} todos")
            return todo_pb2.TodoList(items=self.todos)
        except Exception as e:
            logging.error(f"Error retrieving todos: {str(e)}")
            context.abort(grpc.StatusCode.INTERNAL, f"Error retrieving todos: {str(e)}")

    def DeleteTodo(self, request, context):
        try:
            initial_length = len(self.todos)
            self.todos = [todo for todo in self.todos if todo.id != request.id]
            
            if len(self.todos) == initial_length:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Todo with ID {request.id} not found")
                
            logging.info(f"Deleted todo with ID: {request.id}")
            return todo_pb2.TodoResponse(message="Todo deleted successfully")
        except Exception as e:
            logging.error(f"Error deleting todo: {str(e)}")
            context.abort(grpc.StatusCode.INTERNAL, f"Error deleting todo: {str(e)}")

def serve():
    try:
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            interceptors=[AuthInterceptor()]
        )
        todo_pb2_grpc.add_TodoServiceServicer_to_server(TodoService(), server)
        server.add_insecure_port('[::]:50051')
        server.start()
        logging.info("gRPC server started on port 50051 with authentication")
        server.wait_for_termination()
    except Exception as e:
        logging.error(f"Server error: {str(e)}")
        raise

if __name__ == '__main__':
    serve()