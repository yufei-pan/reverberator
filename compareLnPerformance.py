import os
import multiCMD
import threading
import time

startTime = time.monotonic()
for _ in range(10000):
	if os.path.exists('test.txt'):
		os.remove('test.txt')
	os.symlink('README.md', 'test.txt')

print(f"Python symlink Execution time: {time.monotonic() - startTime} seconds")

startTime = time.monotonic()
sem = threading.Semaphore(64)
mcae =  multiCMD.AsyncExecutor(semaphore=sem)
for _ in range(10000):
	mcae.run_command(['ln','-fsT','test.txt','README.md'])
mcae.wait()
print(f"MultiCMD symlink Execution time: {time.monotonic() - startTime} seconds")
