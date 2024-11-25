class SimpleList {
  private:
    String *items;
    int capacity;
    int count;

    void resize(int newCapacity) {
      String *newItems = new String[newCapacity];
      for (int i = 0; i < count; i++) {
        newItems[i] = items[i];
      }
      delete[] items;
      items = newItems;
      capacity = newCapacity;
    }

  public:
    SimpleList(int initialCapacity = 2) : capacity(initialCapacity), count(0) {
      items = new String[capacity];
    }

    ~SimpleList() {
      delete[] items;
    }

    void add(const String &item) {
      if (count == capacity) {
        resize(capacity * 2);
      }
      items[count++] = item;
    }

    String get(int index) const {
      if (index >= 0 && index < count) {
        return items[index];
      }
      return "";
    }

    String& operator[](int index) {
      return items[index];
    }

    int size() const {
      return count;
    }
};
