# coding=utf-8
import os
import judger

base_path = os.path.dirname(os.path.abspath(__file__))


def run(use_sandbox, use_nobody):
    return judger.run(path="./a.out",
                      in_file=os.path.join(base_path, "in"),
                      out_file=os.path.join(base_path, "out"),
                      # ms
                      max_cpu_time=2000,
                      # Byte
                      max_memory=200000000,
                      # args env and log_path are optional
                      args=["link"],
                      env=["PATH=" + os.environ["PATH"]],
                      log_path="run.log",
                      # default is True
                      use_sandbox=use_sandbox,
                      use_nobody=use_nobody)


print run(use_sandbox=False, use_nobody=False)
