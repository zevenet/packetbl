#ifndef DIRECTRESOLV_H
#define DIRECTRESOLV_H

#include <ldns/ldns.h>

// configuring resolvers

// configure de resolver to send request to a dns directly
// return -1 on failure or 0 on success
int configure_direct_nameserver ( ldns_resolver **res, char* filename )
{
	ldns_status s;
   
	s = ldns_resolver_new_frm_file(res, filename);
	
	// fail
    if (s != LDNS_STATUS_OK) {
		return -1;
    }
	
	return 0;
}


// dns query 
// return 1 if the dns server has resolved
int dns_query ( ldns_resolver *res, char * domain_str )
{
    ldns_rdf *domain = NULL;
	int resolved = 0;

	/* create a rdf from the command line arg */
	domain = ldns_dname_new_frm_str( domain_str );
	if (!domain) {
	    return 0;
	}
	
	// IPv4
	ldns_rr_type wanted_types = LDNS_RR_TYPE_A;
	// IPv6
	//~ ldns_rr_type wanted_types = LDNS_RR_TYPE_AAAA;
	ldns_pkt *p = NULL;
	
	p = ldns_resolver_query(res,
					domain,
					wanted_types,
					LDNS_RR_CLASS_IN,
					LDNS_RD);
	    
	// found 
	ldns_rr_list *result=ldns_pkt_rr_list_by_type(p,wanted_types,LDNS_SECTION_ANSWER);
	
	if (result)
	{
		resolved=1;
	}
	if (p)
		ldns_pkt_free(p);
	ldns_rr_list_deep_free(result);
	ldns_rdf_deep_free(domain);
	
	return resolved;
}


#endif

