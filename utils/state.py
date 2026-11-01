from collections import OrderedDict


# noinspection PyUnresolvedReferences
class MetaClassForInit(type):
    def __new__(mcs, *args, **kwargs):
        new_class = super().__new__(mcs, *args, **kwargs)
        if getattr(new_class, 'cls_init', None):
            new_class.cls_init()
        return new_class


class StateBase(metaclass=MetaClassForInit):
    _keys = []
    _values = []
    _value2key = {}
    _items = None

    @classmethod
    def keys(cls):
        return cls._keys

    @classmethod
    def values(cls):
        return cls._values

    @classmethod
    def v2k(cls, value):
        return cls._value2key[value]

    @classmethod
    def items(cls):
        if cls._items is None:
            cls._items = []
            for k, v in zip(cls.keys(), cls.values()):
                cls._items.append(
                    (k, v),
                )
        return cls._items

    @classmethod
    def to_dict(cls):
        return dict(cls.items())

    @classmethod
    def cls_init(cls):
        _v2k, v2k = {}, OrderedDict()

        for k, v in cls.__dict__.items():
            if k.isupper() and type(v) == int:
                _v2k[v] = k

        for i in sorted(_v2k.keys()):
            v2k[i] = _v2k[i]

        cls._keys = list(v2k.values())
        cls._values = list(v2k.keys())
        cls._value2key = v2k
