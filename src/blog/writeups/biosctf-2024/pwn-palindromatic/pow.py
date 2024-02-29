from time import time
def solve_pow(s, debug=False):
    start = time()
    g = int(s.split("^")[0])
    p = int(s.split("mod ")[1].split(" == ")[0])
    target = int(s.split(" == ")[1])
    i = 0
    while True:
        if pow(g, i, p) == target:
            if debug: print(f'Time taken: {time()-start}')
            return i
        i += 1

# Pass the PoW line given by the challenge to this function 
print(solve_pow(input(), debug=True))