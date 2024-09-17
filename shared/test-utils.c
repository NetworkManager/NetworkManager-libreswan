#include "nm-default.h"

#include "nm-utils/nm-shared-utils.h"

#include "utils.h"

static void
test_parse_subnets (void)
{
	GError *error = NULL;
	gboolean ret;

	/*
	 * Positive cases.
	 */

	ret = nm_libreswan_parse_subnets ("", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1,10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24,10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16,,", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);


	ret = nm_libreswan_parse_subnets ("10.0.0.1, 10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	/*
	 * Negative cases.
	 */

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24meh", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24meh,10.10.0.0/16", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16meh", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1, 10.10.0.0/16,a", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16,b", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1, 10.10.0.0/16,a,", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("boo, 10.0.0.1/24, 10.10.0.0/16", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	/*
	 * No GError.
	 */

	ret = nm_libreswan_parse_subnets ("", NULL, NULL);
	g_assert (ret);

	ret = nm_libreswan_parse_subnets ("boo", NULL, NULL);
	g_assert_false (ret);

}

static void
test_normalize_subnets (void)
{
	GError *error = NULL;
	gchar *str;

	/*
	 * Positive cases.
	 */

	str = nm_libreswan_normalize_subnets ("", &error);
	g_assert_cmpstr (str, ==, "");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1,10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24,10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16,,", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1, 10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	/*
	 * Negative cases.
	 */

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24meh", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24meh,10.10.0.0/16", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16meh", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1, 10.10.0.0/16,a", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16,b", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1, 10.10.0.0/16,a,", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("boo, 10.0.0.1/24, 10.10.0.0/16", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	/*
	 * No GError.
	 */

	str = nm_libreswan_normalize_subnets ("", NULL);
	g_assert_cmpstr (str, ==, "");
	g_free (str);

	str = nm_libreswan_normalize_subnets ("boo", NULL);
	g_assert_null (str);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/utils/subnets/parse", test_parse_subnets);
	g_test_add_func ("/utils/subnets/normalize", test_normalize_subnets);

	return g_test_run ();
}
