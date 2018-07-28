class Switch:
    index = None
    bucket_size = None
    # selector
    selector = None
    # flow count
    flow_count = None
    # flow count total
    flow_count_total = None

    def __init__(self, index, bucket_size):
        self.index = index
        self.bucket_size = bucket_size
        self.selector = []
        self.flow_count = {}
        self.flow_count_total = 0

    def receive(self, addr, flags=0):
        bucket = addr % self.bucket_size
        if bucket in self.selector:
            if flags == 0:
                # SYN
                self.__inc_flow_count(bucket)
            elif flags == 10:
                # FIN
                self.__dec_flow_count(bucket)

    def add_bucket(self, bucket):
        self.selector.append(bucket)
        # if self.index == 0 and bucket < 100:
        #     print self.selector
        #     print bucket, ', ', len(self.selector)

    def remove_bucket(self, bucket):
        self.selector.remove(bucket)

    def read_flow_count(self):
        return self.flow_count_total, self.flow_count

    def clear_flow_count(self):
        self.flow_count.clear()
        self.flow_count_total = 0

    def __inc_flow_count(self, bucket):
        if self.flow_count.has_key(bucket):
            self.flow_count[bucket] = self.flow_count[bucket] + 1
        else:
            self.flow_count[bucket] = 1
        self.flow_count_total = self.flow_count_total + 1

    def __dec_flow_count(self, bucket):
        if self.flow_count.has_key(bucket) and self.flow_count.get(bucket) > 0:
            self.flow_count[bucket] = self.flow_count[bucket] - 1
        else:
            self.flow_count[bucket] = 0
        if self.flow_count_total > 0:
            self.flow_count_total = self.flow_count_total - 1

    def __hash(self, raw):
        return hash(raw) % self.bucket_size