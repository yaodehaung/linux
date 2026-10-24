// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for the MGLRU PID controller (see "PID controller" in vmscan.c).
 * Included at the end of vmscan.c so that it can reach static functions.
 */

#ifdef CONFIG_LRU_GEN_PID_KUNIT_TEST

#include <kunit/test.h>

/* a node of its own, so that the half-life is per test */
static struct lruvec *pid_test_lruvec(struct kunit *test)
{
	struct pglist_data *pgdat = kunit_kzalloc(test, sizeof(*pgdat), GFP_KERNEL);
	struct lruvec *lruvec;
	int gen;

	KUNIT_ASSERT_NOT_NULL(test, pgdat);
	lruvec = &pgdat->__lruvec;
#ifdef CONFIG_MEMCG
	lruvec->pgdat = pgdat;
#endif
	spin_lock_init(&lruvec->lru_lock);
	for (gen = 0; gen < MAX_NR_GENS; gen++)
		lruvec->lrugen.timestamps[gen] = jiffies;

	return lruvec;
}

static void pid_test_set_halflife(struct lruvec *lruvec, int halflife_ms)
{
	WRITE_ONCE(lruvec_pgdat(lruvec)->lru_gen_pid_halflife_ms, halflife_ms);
}

/* make the generation being evicted @age_ms old */
static void pid_test_set_age(struct lruvec *lruvec, int type, unsigned int age_ms)
{
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int gen = lru_gen_from_seq(lrugen->min_seq[type]);

	lrugen->timestamps[gen] = jiffies - msecs_to_jiffies(age_ms);
}

/* fill one tier: the I term (avg) and the generation being evicted (cur) */
static void pid_test_set_tier(struct lruvec *lruvec, int type, int tier,
			      unsigned long avg_r, unsigned long avg_t,
			      unsigned long cur_r, unsigned long cur_t)
{
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int hist = lru_hist_from_seq(lrugen->min_seq[type]);

	lrugen->avg_refaulted[type][tier] = avg_r;
	lrugen->avg_total[type][tier] = avg_t;
	atomic_long_set(&lrugen->refaulted[hist][type][tier], cur_r);
	atomic_long_set(&lrugen->evicted[hist][type][tier], cur_t);
	lrugen->protected[hist][type][tier] = 0;
}

/* halving every half-life, linear in between */
static void pid_test_discount(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ctrl_discount(1000, 0, 100), 1000UL);
	KUNIT_EXPECT_EQ(test, ctrl_discount(1000, 100, 100), 500UL);
	KUNIT_EXPECT_EQ(test, ctrl_discount(1000, 200, 100), 250UL);
	KUNIT_EXPECT_EQ(test, ctrl_discount(1000, 150, 100), 375UL);
	KUNIT_EXPECT_EQ(test, ctrl_discount(1000, 50, 100), 750UL);
	KUNIT_EXPECT_EQ(test, ctrl_discount(ULONG_MAX, 100 * BITS_PER_LONG, 100), 0UL);
	/* 0 disables it */
	KUNIT_EXPECT_EQ(test, ctrl_discount(1000, 1000000, 0), 1000UL);
}

/* halflife=0 must reduce to the original PI controller, however old */
static void pid_test_disabled_is_pi(struct kunit *test)
{
	struct lruvec *lruvec = pid_test_lruvec(test);
	struct ctrl_pos pos;

	pid_test_set_halflife(lruvec, 0);
	pid_test_set_tier(lruvec, LRU_GEN_FILE, 1, 100, 1000, 500, 1000);
	pid_test_set_age(lruvec, LRU_GEN_FILE, 60000);
	read_ctrl_pos(lruvec, LRU_GEN_FILE, 1, 3, &pos);

	KUNIT_EXPECT_EQ(test, pos.refaulted, 600UL);
	KUNIT_EXPECT_EQ(test, pos.total, 2000UL);
	KUNIT_EXPECT_EQ(test, pos.gain, 3);
}

/* a young generation keeps the I term */
static void pid_test_young(struct kunit *test)
{
	struct lruvec *lruvec = pid_test_lruvec(test);
	struct ctrl_pos pos;

	pid_test_set_halflife(lruvec, 1000000);
	pid_test_set_tier(lruvec, LRU_GEN_FILE, 1, 100, 1000, 500, 1000);
	read_ctrl_pos(lruvec, LRU_GEN_FILE, 1, 3, &pos);

	KUNIT_EXPECT_EQ(test, pos.refaulted, 600UL);
	KUNIT_EXPECT_EQ(test, pos.total, 2000UL);
}

/* the I term is discounted by age; the P term is not */
static void pid_test_old(struct kunit *test)
{
	struct lruvec *lruvec = pid_test_lruvec(test);
	struct ctrl_pos pos;

	pid_test_set_halflife(lruvec, 1000);
	pid_test_set_tier(lruvec, LRU_GEN_FILE, 1, 1024, 2048, 500, 1000);

	/* one half-life, give or take the jiffies that tick during the test */
	pid_test_set_age(lruvec, LRU_GEN_FILE, 1000);
	read_ctrl_pos(lruvec, LRU_GEN_FILE, 1, 3, &pos);
	KUNIT_EXPECT_GE(test, pos.refaulted, 500UL + 500);
	KUNIT_EXPECT_LE(test, pos.refaulted, 500UL + 512);
	KUNIT_EXPECT_GE(test, pos.total, 1000UL + 1000);
	KUNIT_EXPECT_LE(test, pos.total, 1000UL + 1024);

	/* many half-lives: only the P term is left */
	pid_test_set_age(lruvec, LRU_GEN_FILE, 1000 * 20);
	read_ctrl_pos(lruvec, LRU_GEN_FILE, 1, 3, &pos);
	KUNIT_EXPECT_EQ(test, pos.refaulted, 500UL);
	KUNIT_EXPECT_EQ(test, pos.total, 1000UL);
}

/* each node discounts by its own half-life */
static void pid_test_per_node(struct kunit *test)
{
	struct lruvec *node0 = pid_test_lruvec(test);
	struct lruvec *node1 = pid_test_lruvec(test);
	struct ctrl_pos pos0, pos1;

	pid_test_set_halflife(node0, 0);
	pid_test_set_halflife(node1, 1000);

	pid_test_set_tier(node0, LRU_GEN_FILE, 1, 1024, 2048, 500, 1000);
	pid_test_set_tier(node1, LRU_GEN_FILE, 1, 1024, 2048, 500, 1000);
	pid_test_set_age(node0, LRU_GEN_FILE, 1000 * 20);
	pid_test_set_age(node1, LRU_GEN_FILE, 1000 * 20);

	read_ctrl_pos(node0, LRU_GEN_FILE, 1, 3, &pos0);
	read_ctrl_pos(node1, LRU_GEN_FILE, 1, 3, &pos1);

	KUNIT_EXPECT_EQ(test, pos0.refaulted, 1024UL + 500);
	KUNIT_EXPECT_EQ(test, pos0.total, 2048UL + 1000);
	KUNIT_EXPECT_EQ(test, pos1.refaulted, 500UL);
	KUNIT_EXPECT_EQ(test, pos1.total, 1000UL);
}

/* a birth time ahead of jiffies (e.g., racing with the aging) is age 0 */
static void pid_test_future_birth(struct kunit *test)
{
	struct lruvec *lruvec = pid_test_lruvec(test);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	struct ctrl_pos pos;

	pid_test_set_halflife(lruvec, 1);
	pid_test_set_tier(lruvec, LRU_GEN_FILE, 1, 100, 1000, 500, 1000);
	lrugen->timestamps[lru_gen_from_seq(lrugen->min_seq[LRU_GEN_FILE])] = jiffies + HZ;
	read_ctrl_pos(lruvec, LRU_GEN_FILE, 1, 3, &pos);

	KUNIT_EXPECT_EQ(test, pos.refaulted, 600UL);
	KUNIT_EXPECT_EQ(test, pos.total, 2000UL);
}

/*
 * Build up the I term with @before permille refaults in tier 1 for many
 * generations (tier 0 is fixed at 10%), then start a generation in which tier 1
 * refaults at @after permille, and let it live longer and longer. Returns the
 * age in half-lives (x2) at which get_tier_idx() first changed (-1 if never),
 * and counts how often it changed in @flips.
 */
#define PID_SIM_TOTAL		1000
#define PID_SIM_WARMUP		16
#define PID_SIM_HALFLIFE	1000
#define PID_SIM_STEPS		16

static void pid_sim_evict(struct lruvec *lruvec, int type, int tier, unsigned int rate)
{
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int hist = lru_hist_from_seq(lrugen->min_seq[type]);

	atomic_long_add(PID_SIM_TOTAL / 2 * rate / 1000, &lrugen->refaulted[hist][type][tier]);
	atomic_long_add(PID_SIM_TOTAL / 2, &lrugen->evicted[hist][type][tier]);
}

static void pid_sim_next_gen(struct lruvec *lruvec, int type)
{
	struct lru_gen_folio *lrugen = &lruvec->lrugen;
	int hist, tier;

	spin_lock(&lruvec->lru_lock);
	reset_ctrl_pos(lruvec, type, true);
	spin_unlock(&lruvec->lru_lock);

	/* what the aging clears for a recycled hist when NR_HIST_GENS > 1 */
	lrugen->min_seq[type]++;
	hist = lru_hist_from_seq(lrugen->min_seq[type]);
	for (tier = 0; tier < MAX_NR_TIERS; tier++) {
		atomic_long_set(&lrugen->refaulted[hist][type][tier], 0);
		atomic_long_set(&lrugen->evicted[hist][type][tier], 0);
		lrugen->protected[hist][type][tier] = 0;
	}
	pid_test_set_age(lruvec, type, 0);
}

static int pid_sim(struct kunit *test, int halflife_ms, unsigned int before,
		   unsigned int after, int *flips)
{
	struct lruvec *lruvec = pid_test_lruvec(test);
	const int type = LRU_GEN_FILE;
	int gen, step, idx, last, when = -1;

	pid_test_set_halflife(lruvec, halflife_ms);
	*flips = 0;

	for (gen = 0; gen < PID_SIM_WARMUP; gen++) {
		pid_sim_evict(lruvec, type, 0, 100);
		pid_sim_evict(lruvec, type, 1, before);
		pid_sim_evict(lruvec, type, 0, 100);
		pid_sim_evict(lruvec, type, 1, before);
		pid_sim_next_gen(lruvec, type);
	}

	/* half of the long-lived generation evicted, then it just gets older */
	pid_sim_evict(lruvec, type, 0, 100);
	pid_sim_evict(lruvec, type, 1, after);
	last = get_tier_idx(lruvec, type);

	for (step = 1; step <= PID_SIM_STEPS; step++) {
		pid_test_set_age(lruvec, type, PID_SIM_HALFLIFE * step / 2);
		idx = get_tier_idx(lruvec, type);
		if (idx != last) {
			if (when < 0)
				when = step;
			(*flips)++;
		}
		last = idx;
	}

	kunit_info(test, "halflife=%dms %u->%u permille: changed at %d/2 half-lives, flips=%d\n",
		   halflife_ms, before, after, when, *flips);

	return when;
}

/* tier 1 turned cold, but the I term says hot: protection must expire */
static void pid_test_sim_stale_hot(struct kunit *test)
{
	int pi_flips, pid_flips;

	KUNIT_EXPECT_EQ(test, pid_sim(test, 0, 400, 20, &pi_flips), -1);
	KUNIT_EXPECT_GT(test, pid_sim(test, PID_SIM_HALFLIFE, 400, 20, &pid_flips), 0);
	KUNIT_EXPECT_EQ(test, pid_flips, 1);
}

/* tier 1 turned hot, but the I term says cold: protection must kick in */
static void pid_test_sim_stale_cold(struct kunit *test)
{
	int pi_flips, pid_flips;

	KUNIT_EXPECT_EQ(test, pid_sim(test, 0, 20, 250, &pi_flips), -1);
	KUNIT_EXPECT_GT(test, pid_sim(test, PID_SIM_HALFLIFE, 20, 250, &pid_flips), 0);
	KUNIT_EXPECT_EQ(test, pid_flips, 1);
}

/* when the I term is not stale, age alone must not flip anything */
static void pid_test_sim_steady(struct kunit *test)
{
	int flips;

	KUNIT_EXPECT_EQ(test, pid_sim(test, PID_SIM_HALFLIFE, 20, 20, &flips), -1);
	KUNIT_EXPECT_EQ(test, pid_sim(test, PID_SIM_HALFLIFE, 400, 400, &flips), -1);
}

static struct kunit_case pid_test_cases[] = {
	KUNIT_CASE(pid_test_discount),
	KUNIT_CASE(pid_test_disabled_is_pi),
	KUNIT_CASE(pid_test_young),
	KUNIT_CASE(pid_test_old),
	KUNIT_CASE(pid_test_per_node),
	KUNIT_CASE(pid_test_future_birth),
	KUNIT_CASE(pid_test_sim_stale_hot),
	KUNIT_CASE(pid_test_sim_stale_cold),
	KUNIT_CASE(pid_test_sim_steady),
	{},
};

static struct kunit_suite pid_test_suite = {
	.name = "mglru-pid",
	.test_cases = pid_test_cases,
};
kunit_test_suite(pid_test_suite);

#endif /* CONFIG_LRU_GEN_PID_KUNIT_TEST */
