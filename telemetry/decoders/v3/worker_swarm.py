# v0.0.1
#
# DISCLAIMER, I didn't do Python for more than 10 years before writing that code :-D
#
# This is a STRONG WARNING, it means that this code might not follow best practises in Python, and
# even worse that this code might not be do what it is supposed to do.
#
# Micro-library to do computation in a multi (thread|process) manner
#
# Python threads are spreading on multiple cores, Python processes are real
# UNIX processes that are spreading on multiple cores.
#
# This library provides two implementations:
# - WorkerSwarmMP for multi-processes version
# - WorkerSwarmMT for multi-thread version
#
# Trade-off:
# - MP tasks are a bit heavier to start and tasks distribution is a bit less efficient
# - MP tasks are really spreading on all the available CPU and therefore achieve better
#   results on multiple core.
#
# Raphaël P. Barazzutti - raphael@barazzutti.net

__all__ = ['WorkerSwarmMP', 'WorkerSwarmMT']


def prepare(t, q):
    class WorkerThread(t):

        def __init__(self, queue, context, transform_function):
            super().__init__()
            self.__queue = queue
            self.__state = context
            self.__transformFunction = transform_function

        def run(self):
            while True:
                submission = self.__queue.get(block=True)
                if submission is not None:
                    ret = self.__transformFunction(self.__state, submission.job)
                    if submission.callback is not None:
                        submission.callback(ret)
                else:
                    return

    class WorkerSwarm:

        def enqueue(self, job, callback=None):
            self.__queue.put(WorkerTask(job, callback))

        def __init__(self, number_of_workers, state_builder, transform_function):
            self.__queue = q()
            self.__threads = []
            for i in range(0, number_of_workers):
                t = WorkerThread(self.__queue, state_builder(), transform_function)
                self.__threads.append(t)

        def start(self):
            for thread in self.__threads:
                thread.daemon = True
                thread.start()

        def wait(self):
            for thread in self.__threads:
                thread.join()

        def stop(self):
            for thread in self.__threads:
                self.__queue.put(None, block=True)

    return WorkerSwarm


class WorkerTask:
    def __init__(self, job, callback):
        super().__init__()
        self.job = job
        self.callback = callback


def prepare_multi_thread():
    from queue import Queue
    from threading import Thread

    return prepare(Thread, Queue)


WorkerSwarmMT = prepare_multi_thread()


def prepare_multi_process():
    from multiprocessing import Process
    from multiprocessing import Queue

    return prepare(Process, Queue)


WorkerSwarmMP = prepare_multi_process()
