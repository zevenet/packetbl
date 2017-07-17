#ifndef DIRECTRESOLV_H
#define DIRECTRESOLV_H

#include <ldns/ldns.h>


// https://github.com/cvigano/dnsutils-ldns/blob/master/src/host.c
// dnsutils-ldns
ldns_rr_list* dnsutils_retrieve_rr_lists(ldns_pkt *p, ldns_rr_type t, ldns_pkt_section s) {
  ldns_rr_list *tmp = ldns_pkt_rr_list_by_type(p, t, s);

  if (!tmp) {
    ldns_pkt_free(p);
  } else {
    ldns_rr_list_sort(tmp);
  }
  return tmp;
}


// A, AAAA, MX records 
ldns_rr_list** dnsutils_complete_questioning(ldns_resolver *res, ldns_rdf *domain) {
    
    ldns_rr_list** all_records = malloc(2 * sizeof(ldns_rr_list));
    ldns_rr_type wanted_types[2] = { LDNS_RR_TYPE_A, LDNS_RR_TYPE_AAAA };
	int i;

    if(!all_records) {
	return NULL;
    }
    for (i = 0; i < 2; i++) 
    {
		ldns_pkt *p = NULL;
		p = ldns_resolver_query(res,
					domain,
					wanted_types[i],
					LDNS_RR_CLASS_IN,
					LDNS_RD);
		if(!p) {
			// TODO: correct error handling
			all_records[i] = NULL;
		} else {
			all_records[i] = dnsutils_retrieve_rr_lists(p,
								wanted_types[i],
								LDNS_SECTION_ANSWER);
		}
    }
    
    return all_records;
}


// configure de resolver to send request to a dns directly
// return -1 on failure or 0 on success
int configure_direct_nameserver ( ldns_resolver **res, char* filename )
{
	ldns_status s;
	//~ res = NULL;
   
	s = ldns_resolver_new_frm_file(res, filename);

	// fail
    if (s != LDNS_STATUS_OK) {
		return -1;
    }
	
	return 0;
}


// delete the sturct used for the resolv configuration
int unset_direct_nameserver ( ldns_resolver *res )
{
	ldns_resolver_deep_free(res);
}


// return 1 if the dns server has resolved
int direct_dns_resolv ( ldns_resolver *res, char * domain_str )
{
    ldns_rdf *domain = NULL;
	int resolved = 0;
	int  i, j;

	
	/* create a rdf from the command line arg */
	domain = ldns_dname_new_frm_str( domain_str );
	if (!domain) {
	    return 0;
	    exit(EXIT_FAILURE);
	}
    ldns_rr_list** results = dnsutils_complete_questioning(res, domain);
    for (i = 0; i < 2; ++i){
	for (j = 0; j < ldns_rr_list_rr_count(results[i]) && results[i]; ++j) {
	    ldns_rr* rr = ldns_rr_list_rr(results[i], j);

	    ldns_rdf* rdf = ldns_rr_pop_rdf(rr);

	    switch(ldns_rdf_get_type(rdf)) {
	    case LDNS_RDF_TYPE_A:
	    resolved = 1;
		break;
	    case LDNS_RDF_TYPE_AAAA:
	    resolved = 1;
		break;
	    default:
		printf ("%s\n", "something different");
		break;
	    }
	    ldns_rdf_deep_free(rdf);
	}
    }
	// Free resources
	ldns_rr_list_deep_free(*results);
    
    return resolved;
}


#endif
