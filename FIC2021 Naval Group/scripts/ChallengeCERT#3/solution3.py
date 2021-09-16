# coding=utf-8
import string


def xor(data, key):
    return [data[i] ^ key[i % len(key)] for i in range(len(data))]


def tobin(s):
    return list(map(int, list("".join(["{:08b}".format(s[i]) for i in range(len(s))]))))


def tobytes(s):
    bs = "".join(list(map(str, s)))
    return [int(bs[i:i + 8], 2) for i in range(0, len(bs), 8)]


def trans(b):
    res = []
    for i in range(576):
        res.append(b[(i - 1) % 576 if i != 0 else 575] ^ ((b[i] == 0) and (b[(i + 1) % 576] == 0)))
    return res


def score(a, b):
    for i in range(len(a)):
        if a[i] != b[i]:
            return i
    return 999


def go(s):
    return tobytes(trans(trans(trans(trans(trans(tobin(s)))))))


def find_last_char():
    best = (0, None)
    for c1 in charset:
        s1[-1] = c1
        r = score(go(xor(s1, key)), reference)
        if r >= best[0]:
            best = (r, c1)
    print("Last char is", best[1])  # i or I
    s1[-1] = best[1]
    print("".join(map(chr, s1)))


if __name__ == '__main__':

    key = list(open("key", "rb").read())
    reference = list(open("reference", "rb").read())

    charset = list(map(ord, string.ascii_lowercase + string.ascii_uppercase + string.digits + "-"))

    base = "https://dropfile.naval-group.com/pfv2-sharing/sharings/aaaaaaaa.aaaaaaaI"
    s1 = list(map(ord, base))

    # Find last char
    # find_last_char() -> I

    # Bruteforce two next chars and get the best results
    i = 55
    best = [0, set()]
    for c1 in charset:
        s1[i] = c1
        for c2 in charset:
            s1[i + 1] = c2
            r = score(go(xor(s1, key)), reference)
            if r > best[0]:
                best = [r, {c1}]
            elif r == best[0]:
                best[1].add(c1)
    print("Best char for", i, "is", list(map(chr, best[1])))
