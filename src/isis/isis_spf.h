/*
 * IS-IS Rout(e)ing protocol - isis_spf.h
 *                             IS-IS Shortest Path First algorithm  
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ISIS_SPF_H_
#define _ISIS_SPF_H_

enum vertextype
{
  VTYPE_PSEUDO_IS = 1,
  VTYPE_PSEUDO_TE_IS,
  VTYPE_NONPSEUDO_IS,
  VTYPE_NONPSEUDO_TE_IS,
  VTYPE_ES,
  VTYPE_IPREACH_INTERNAL,
  VTYPE_IPREACH_EXTERNAL,
  VTYPE_IPREACH_TE,
  VTYPE_IP6REACH_INTERNAL,
  VTYPE_IP6REACH_EXTERNAL
};

/*
 * Triple <N, d(N), {Adj(N)}> 
 */
struct isis_vertex
{
  enum vertextype type;

  union
  {
    u_char id[ISIS_SYS_ID_LEN + 1];
    struct isis_prefix prefix;
  } N;

  struct isis_lsp *lsp;
  u_int32_t d_N;		/* d(N) Distance from this IS      */
  u_int16_t depth;		/* The depth in the imaginary tree */

  struct pm_list *Adj_N;		/* {Adj(N)}  */
};

struct isis_spftree
{
  struct thread *t_spf;		/* spf threads */
  time_t lastrun;		/* for scheduling */
  int pending;			/* already scheduled */
  struct pm_list *paths;		/* the SPT */
  struct pm_list *tents;		/* TENT */

  u_int32_t timerun;		/* statistics */
};

extern void spftree_area_init (struct isis_area *);
extern int isis_spf_schedule (struct isis_area *, int);
extern int isis_run_spf (struct isis_area *, int, int);
extern int isis_spf_schedule6 (struct isis_area *, int);

#endif /* _ISIS_SPF_H_ */
