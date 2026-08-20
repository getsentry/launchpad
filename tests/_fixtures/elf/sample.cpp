namespace launchpad {

class Widget {
public:
    virtual ~Widget();
    virtual int render(int value) const;
    static int count;
    static int pending;
};

Widget::~Widget() = default;

int Widget::render(int value) const {
    return value + count;
}

int Widget::count = 7;
int Widget::pending;

int helper(int value) {
    return value * 2;
}

}

extern "C" int launchpad_entry(int value) {
    launchpad::Widget widget;
    return widget.render(launchpad::helper(value));
}
