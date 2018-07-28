class Switch:
    index = None
    bucket_size = None
    up = None
    cleared = None
    # selector
    selector = None
    # flow count
    __flow_count = None
    # flow count total
    __flow_count_total = None

    def __init__(self, index, bucket_size):
        self.up = True
        self.cleared = False
        self.index = index
        self.bucket_size = bucket_size
        self.selector = []
        self.__flow_count = {}
        self.__flow_count_total = 0

    def receive(self, addr, flags=0):
        bucket = addr % self.bucket_size
        if bucket in self.selector:
            if flags == 0:
                # SYN
                self.__inc_flow_count(bucket)
            elif flags == 10:
                # FIN
                self.__dec_flow_count(bucket)

    def shutdown(self):
        self.up = False

    def clear(self):
        # redistribute all the bucket it has
        self.cleared = True

    def add_bucket(self, bucket):
        self.selector.append(bucket)
        # if self.index == 0 and bucket < 100:
        #     print self.selector
        #     print bucket, ', ', len(self.selector)

    def remove_bucket(self, bucket):
        self.selector.remove(bucket)

    def read_flow_count(self):
        if self.up:
            total = self.__flow_count_total
        else:
            total = 0
        return total, self.__flow_count

    def clear_flow_count(self):
        self.__flow_count.clear()
        self.__flow_count_total = 0

    def __inc_flow_count(self, bucket):
        if self.__flow_count.has_key(bucket):
            self.__flow_count[bucket] = self.__flow_count[bucket] + 1
        else:
            self.__flow_count[bucket] = 1
        self.__flow_count_total = self.__flow_count_total + 1

    def __dec_flow_count(self, bucket):
        if self.__flow_count.has_key(bucket) and self.__flow_count.get(bucket) > 0:
            self.__flow_count[bucket] = self.__flow_count[bucket] - 1
        else:
            self.__flow_count[bucket] = 0
        if self.__flow_count_total > 0:
            self.__flow_count_total = self.__flow_count_total - 1

    def __hash(self, raw):
        return hash(raw) % self.bucket_size