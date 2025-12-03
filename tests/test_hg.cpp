#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <pvac/pvac.hpp>

using namespace pvac;

struct Adj { std::vector<std::vector<int>> ev, ve; };
struct St { double mu, sd; int lo, hi; };

Adj build(const PubKey& pk) {
    int m = pk.prm.m_bits, n = pk.prm.n_bits;
    Adj a; a.ev.assign(n, {}); a.ve.assign(m, {});
    for (int c = 0; c < n; ++c) {
        const BitVec& col = pk.H[c];
        for (size_t wi = 0; wi < col.w.size(); ++wi) {
            uint64_t x = col.w[wi];
            while (x) {
                int r = wi * 64 + __builtin_ctzll(x);
                if (r < m) { a.ev[c].push_back(r); a.ve[r].push_back(c); }
                x &= x - 1;
            }
        }
    }
    return a;
}

St stat(const std::vector<int>& v) {
    if (v.empty()) return {0,0,0,0};
    double s = 0, s2 = 0; int lo = v[0], hi = v[0];
    for (int x : v) { s += x; s2 += x*x; lo = std::min(lo,x); hi = std::max(hi,x); }
    double mu = s / v.size();
    return {mu, std::sqrt(std::max(0.0, s2/v.size() - mu*mu)), lo, hi};
}

int comps(const Adj& a, int& largest) {
    int m = a.ve.size(), n = a.ev.size(), cnt = 0;
    std::vector<bool> vv(m), ve(n);
    largest = 0;
    for (int s = 0; s < m; ++s) {
        if (vv[s]) continue;
        cnt++;
        std::vector<int> q = {s};
        vv[s] = true;
        for (size_t i = 0; i < q.size(); ++i) {
            for (int e : a.ve[q[i]]) {
                if (ve[e]) continue;
                ve[e] = true;
                for (int u : a.ev[e]) {
                    if (!vv[u]) { vv[u] = true; q.push_back(u); }
                }
            }
        }
        largest = std::max(largest, (int)q.size());
    }
    return cnt;
}

St inter(const Adj& a) {
    int n = a.ev.size();
    int samp = std::min(n*(n-1)/2, 2000);
    std::vector<int> vals;
    for (int s = 0; s < samp; ++s) {
        int e1 = csprng_u64() % n, e2;
        do { e2 = csprng_u64() % n; } while (e1 == e2);
        const auto &x = a.ev[e1], &y = a.ev[e2];
        size_t i = 0, j = 0; int c = 0;
        while (i < x.size() && j < y.size()) {
            if (x[i] < y[j]) i++;
            else if (x[i] > y[j]) j++;
            else { c++; i++; j++; }
        }
        vals.push_back(c);
    }
    return stat(vals);
}

void hist(const std::vector<int>& v, const char* name, int buckets) {
    int mx = *std::max_element(v.begin(), v.end());
    int w = std::max(1, (mx + buckets) / buckets);
    std::vector<int> cnt(buckets, 0);
    for (int x : v) { int b = x / w; if (b >= buckets) b = buckets - 1; cnt[b]++; }
    std::cout << "  " << name << " buckets (w=" << w << "): ";
    for (int i = 0; i < buckets; ++i)
        std::cout << i*w << "-" << (i+1)*w-1 << ":" << cnt[i] << (i < buckets-1 ? " " : "\n");
}

int main() {
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "- hg test -\n\n";

    Params prm; PubKey pk; SecKey sk;
    keygen(prm, pk, sk);

    int m = pk.prm.m_bits, n = pk.prm.n_bits, k = pk.prm.h_col_wt;
    double lam = (double)n * k / m;

    std::cout << "params:\n";
    std::cout << "\n";

    std::cout << "m (vertices) = " << m << "\n";
    std::cout << "n (hyperedges) = " << n << "\n";
    std::cout << "k (col weight) = " << k << "\n";
    std::cout << "B (group) = " << pk.prm.B << "\n";
    std::cout << "H_digest = 0x" << std::hex << load_le64(pk.H_digest.data()) << std::dec << "\n\n";

    Adj a = build(pk);

    std::vector<int> dv(m), de(n);
    for (int i = 0; i < m; ++i) dv[i] = a.ve[i].size();
    for (int i = 0; i < n; ++i) de[i] = a.ev[i].size();

    auto sv = stat(dv), se = stat(de);

    std::cout << "- stats -\n";
    std::cout << "\n";

    std::cout << "avg vertex deg = " << sv.mu << " (sd = " << sv.sd << ")\n";
    std::cout << "min / max deg = " << sv.lo << " / " << sv.hi << "\n";
    std::cout << "avg edge size = " << se.mu << " (sd = " << se.sd << ")\n";
    std::cout << "min / max edge = " << se.lo << " / " << se.hi << "\n";
    std::cout << "lambda = " << lam << "\n";

    std::cout << "\n";

    hist(dv, "vdeg", 8);
    hist(de, "esz ", 4);

    std::cout << "\n";

    int largest = 0;
    int nc = comps(a, largest);
    double frac = (double)largest / m;

    std::cout << "- components -\n";
    std::cout << "\n";
    
    std::cout << "count = " << nc << "\n";
    std::cout << "largest = " << largest << "\n";
    std::cout << "fraction = " << frac << "\n\n";

    auto is = inter(a);
    double ix = (double)k * k / m;

    std::cout << "- edge intersec -\n";
    std::cout << "\n";
    
    std::cout << "mean = " << is.mu << " (sd = " << is.sd << ")\n";
    std::cout << "range = " << is.lo << " - " << is.hi << "\n";
    std::cout << "expected = " << ix << "\n\n";

    bool ok = (nc == 1) && (std::abs(sv.mu - lam) < 5) && (std::abs(is.mu - ix) < 1);
    std::cout << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}