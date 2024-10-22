# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

import todo_pb2 as todo__pb2

GRPC_GENERATED_VERSION = '1.67.0'
GRPC_VERSION = grpc.__version__
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    raise RuntimeError(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in todo_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
    )


class TodoServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.AddTodo = channel.unary_unary(
                '/todo.TodoService/AddTodo',
                request_serializer=todo__pb2.TodoItem.SerializeToString,
                response_deserializer=todo__pb2.TodoResponse.FromString,
                _registered_method=True)
        self.GetTodos = channel.unary_unary(
                '/todo.TodoService/GetTodos',
                request_serializer=todo__pb2.Empty.SerializeToString,
                response_deserializer=todo__pb2.TodoList.FromString,
                _registered_method=True)
        self.DeleteTodo = channel.unary_unary(
                '/todo.TodoService/DeleteTodo',
                request_serializer=todo__pb2.TodoId.SerializeToString,
                response_deserializer=todo__pb2.TodoResponse.FromString,
                _registered_method=True)


class TodoServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def AddTodo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetTodos(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteTodo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_TodoServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'AddTodo': grpc.unary_unary_rpc_method_handler(
                    servicer.AddTodo,
                    request_deserializer=todo__pb2.TodoItem.FromString,
                    response_serializer=todo__pb2.TodoResponse.SerializeToString,
            ),
            'GetTodos': grpc.unary_unary_rpc_method_handler(
                    servicer.GetTodos,
                    request_deserializer=todo__pb2.Empty.FromString,
                    response_serializer=todo__pb2.TodoList.SerializeToString,
            ),
            'DeleteTodo': grpc.unary_unary_rpc_method_handler(
                    servicer.DeleteTodo,
                    request_deserializer=todo__pb2.TodoId.FromString,
                    response_serializer=todo__pb2.TodoResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'todo.TodoService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('todo.TodoService', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class TodoService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def AddTodo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/todo.TodoService/AddTodo',
            todo__pb2.TodoItem.SerializeToString,
            todo__pb2.TodoResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetTodos(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/todo.TodoService/GetTodos',
            todo__pb2.Empty.SerializeToString,
            todo__pb2.TodoList.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def DeleteTodo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/todo.TodoService/DeleteTodo',
            todo__pb2.TodoId.SerializeToString,
            todo__pb2.TodoResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)