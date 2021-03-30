import inspect
import warnings
from functools import wraps

from six import string_types


# https://stackoverflow.com/questions/2536307/how-do-i-deprecate-python-functions/40301488#40301488
def deprecated(reason):
    """
    This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used.
    """

    if isinstance(reason, string_types):

        # The @deprecated is used with a 'reason'.
        #
        # .. code-block:: python
        #
        #    @deprecated("please, use another function")
        #    def old_function(x, y):
        #      pass

        def decorator(func1):

            if inspect.isclass(func1):
                fmt1 = "Call to deprecated class {name} ({reason})."
            else:
                fmt1 = "Call to deprecated function {name} ({reason})."

            @wraps(func1)
            def new_func1(*args, **kwargs):
                warnings.simplefilter('always', DeprecationWarning)
                warnings.warn(
                    fmt1.format(name=func1.__name__, reason=reason), category=DeprecationWarning, stacklevel=2
                )
                warnings.simplefilter('default', DeprecationWarning)
                return func1(*args, **kwargs)

            return new_func1

        return decorator

    elif inspect.isclass(reason) or inspect.isfunction(reason):

        # The @deprecated is used without any 'reason'.
        #
        # .. code-block:: python
        #
        #    @deprecated
        #    def old_function(x, y):
        #      pass

        func2 = reason

        if inspect.isclass(func2):
            fmt2 = "Call to deprecated class {name}."
        else:
            fmt2 = "Call to deprecated function {name}."

        @wraps(func2)
        def new_func2(*args, **kwargs):
            warnings.simplefilter('always', DeprecationWarning)
            warnings.warn(fmt2.format(name=func2.__name__), category=DeprecationWarning, stacklevel=2)
            warnings.simplefilter('default', DeprecationWarning)
            return func2(*args, **kwargs)

        return new_func2

    else:
        raise TypeError(repr(type(reason)))


@deprecated('Use eduid.webapp.common.api.decorators.deprecated instead')
class Deprecated(object):
    """
    Mark deprecated functions with this decorator.

    Attention! Use it as the closest one to the function you decorate.

    :param message: The deprecation message
    :type message: str | unicode
    """

    def __init__(self, message=None):
        self.message = message

    def __call__(self, func):
        if self.message is None:
            self.message = 'Deprecated function {!r} called'.format(func.__name__)

        @wraps(func)
        def new_func(*args, **kwargs):
            warnings.warn(self.message, category=DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        # work around a bug in functools.wraps thats fixed in python 3.2
        if getattr(new_func, '__wrapped__', None) is None:
            new_func.__wrapped__ = func
        return new_func
