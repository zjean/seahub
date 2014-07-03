# encoding: utf-8

import os
from types import FunctionType
import logging
import simplejson as json
import re
import datetime
import csv, chardet, StringIO

from django.core.urlresolvers import reverse
from django.contrib import messages
from django.http import HttpResponse, Http404, HttpResponseRedirect, \
        HttpResponseBadRequest
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils.translation import ugettext as _

from seaserv import ccnet_threaded_rpc, seafserv_threaded_rpc, get_emailusers, \
    CALC_SHARE_USAGE, seafile_api
import seaserv
from pysearpc import SearpcError

from seahub.base.accounts import User
from seahub.base.models import UserLastLogin, Department, DepartmentUser, \
        DepartmentGroup
from seahub.base.decorators import sys_staff_required
from seahub.auth.decorators import login_required, login_required_ajax
from seahub.utils import IS_EMAIL_CONFIGURED, string2list, is_valid_username
from seahub.views import get_system_default_repo_id
from seahub.forms import SetUserQuotaForm, AddUserForm, BatchAddUserForm
from seahub.profile.models import Profile, DetailedProfile
from seahub.share.models import FileShare

import seahub.settings as settings
from seahub.settings import INIT_PASSWD, SITE_NAME, \
    SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER, SEND_EMAIL_ON_RESETTING_USER_PASSWD
from seahub.utils import send_html_email, get_user_traffic_list, get_server_id
from seahub.utils.sysinfo import get_platform_name

logger = logging.getLogger(__name__)

@login_required
@sys_staff_required
def sys_repo_admin(request):
    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25

    repos_all = seafile_api.get_repo_list(per_page * (current_page -1),
                                          per_page + 1)
    repos = repos_all[:per_page]
    if len(repos_all) == per_page + 1:
        page_next = True
    else:
        page_next = False

    for repo in repos:
        try:
            repo.owner = seafile_api.get_repo_owner(repo.id)
        except:
            repo.owner = "failed to get"

    return render_to_response(
        'sysadmin/sys_repo_admin.html', {
            'repos': repos,
            'current_page': current_page,
            'prev_page': current_page-1,
            'next_page': current_page+1,
            'per_page': per_page,
            'page_next': page_next,
        },
        context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_list_orphan(request):
    try:
        repos = seafile_api.get_orphan_repo_list()
    except Exception as e:
        logger.error(e)
        repos = []

    return render_to_response('sysadmin/sys_list_orphan.html', {
            'repos': repos,
            }, context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_list_system(request):
    """List system repos.
    """
    repos = []
    sys_repo = seafile_api.get_repo(get_system_default_repo_id())
    repos.append(sys_repo)

    return render_to_response('sysadmin/sys_list_system.html', {
            'repos': repos,
            }, context_instance=RequestContext(request))

def list_repos_by_name_and_owner(repo_name, owner):
    repos = []
    owned_repos = seafile_api.get_owned_repo_list(owner)
    for repo in owned_repos:
        if repo_name in repo.name:
            repo.owner = owner
            repos.append(repo)
    return repos

def list_repos_by_name(repo_name):
    repos = []
    repos_all = seafile_api.get_repo_list(-1, -1)
    for repo in repos_all:
        if repo_name in repo.name:
            try:
                repo.owner = seafile_api.get_repo_owner(repo.id)
            except SearpcError:
                repo.owner = "failed to get"
            repos.append(repo)
    return repos

def list_repos_by_owner(owner):
    repos = seafile_api.get_owned_repo_list(owner)
    for e in repos:
        e.owner = owner
    return repos
    
@login_required
@sys_staff_required
def sys_repo_search(request):
    """Search a repo.
    """
    repo_name = request.GET.get('name', '')
    owner = request.GET.get('owner', '')
    repos = []    

    if repo_name and owner : # search by name and owner
        repos = list_repos_by_name_and_owner(repo_name, owner)
    elif repo_name:     # search by name
        repos = list_repos_by_name(repo_name)
    elif owner:     # search by owner
        repos = list_repos_by_owner(owner)

    return render_to_response('sysadmin/sys_repo_search.html', {
            'repos': repos,
            'name': repo_name,
            'owner': owner,
            }, context_instance=RequestContext(request))
    
@login_required
@sys_staff_required
def sys_user_admin(request):
    """List all users from database.
    """
    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25
    users_plus_one = get_emailusers('DB', per_page * (current_page - 1), per_page + 1)
    if len(users_plus_one) == per_page + 1:
        page_next = True
    else:
        page_next = False

    users = users_plus_one[:per_page]
    last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in users])
    for user in users:
        if user.props.id == request.user.id:
            user.is_self = True
        try:
            user.self_usage = seafile_api.get_user_self_usage(user.email)
            user.share_usage = seafile_api.get_user_share_usage(user.email)
            user.quota = seafile_api.get_user_quota(user.email)
        except:
            user.self_usage = -1
            user.share_usage = -1
            user.quota = -1
        # populate user last login time
        user.last_login = None
        for last_login in last_logins:
            if last_login.username == user.email:
                user.last_login = last_login.last_login

    have_ldap = True if len(get_emailusers('LDAP', 0, 1)) > 0 else False

    platform = get_platform_name()
    server_id = get_server_id()

    return render_to_response(
        'sysadmin/sys_useradmin.html', {
            'users': users,
            'current_page': current_page,
            'prev_page': current_page-1,
            'next_page': current_page+1,
            'per_page': per_page,
            'page_next': page_next,
            'CALC_SHARE_USAGE': CALC_SHARE_USAGE,
            'have_ldap': have_ldap,
            'platform': platform,
            'server_id': server_id[:8],
        },
        context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_user_admin_ldap(request):
    """List all users from LDAP.
    """
    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25
    users_plus_one = get_emailusers('LDAP', per_page * (current_page - 1), per_page + 1)
    if len(users_plus_one) == per_page + 1:
        page_next = True
    else:
        page_next = False

    users = users_plus_one[:per_page]
    last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in users])
    for user in users:
        if user.props.id == request.user.id:
            user.is_self = True
        try:
            user.self_usage = seafile_api.get_user_self_usage(user.email)
            user.share_usage = seafile_api.get_user_share_usage(user.email)
            user.quota = seafile_api.get_user_quota(user.email)
        except:
            user.self_usage = -1
            user.share_usage = -1
            user.quota = -1

        # populate user last login time
        user.last_login = None
        for last_login in last_logins:
            if last_login.username == user.email:
                user.last_login = last_login.last_login
            
            
    return render_to_response(
        'sysadmin/sys_useradmin_ldap.html', {
            'users': users,
            'current_page': current_page,
            'prev_page': current_page-1,
            'next_page': current_page+1,
            'per_page': per_page,
            'page_next': page_next,
            'CALC_SHARE_USAGE': CALC_SHARE_USAGE,
        },
        context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_user_admin_admins(request):
    """List all admins from database.
    """
    users = get_emailusers('DB', -1, -1)

    admin_users = []
    not_admin_users = []
    for user in users:
        if user.is_staff is True:
            admin_users.append(user)
        else:
            not_admin_users.append(user)

    last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in admin_users])

    for user in admin_users:
        if user.props.id == request.user.id:
            user.is_self = True
        try:
            user.self_usage = seafile_api.get_user_self_usage(user.email)
            user.share_usage = seafile_api.get_user_share_usage(user.email)
            user.quota = seafile_api.get_user_quota(user.email)
        except:
            user.self_usage = -1
            user.share_usage = -1
            user.quota = -1
        # populate user last login time
        user.last_login = None
        for last_login in last_logins:
            if last_login.username == user.email:
                user.last_login = last_login.last_login

    have_ldap = True if len(get_emailusers('LDAP', 0, 1)) > 0 else False

    return render_to_response(
        'sysadmin/sys_useradmin_admins.html', {
            'admin_users': admin_users,
            'not_admin_users': not_admin_users,
            'CALC_SHARE_USAGE': CALC_SHARE_USAGE,
            'have_ldap': have_ldap,
        },
        context_instance=RequestContext(request))

@login_required
@sys_staff_required
def user_info(request, email):

    owned_repos = seafile_api.get_owned_repo_list(email)

    quota = seafile_api.get_user_quota(email)
    quota_usage = 0
    share_usage = 0
    my_usage = 0
    my_usage = seafile_api.get_user_self_usage(email)
    if CALC_SHARE_USAGE:
        try:
            share_usage = seafile_api.get_user_share_usage(email)
        except SearpcError, e:
            logger.error(e)
            share_usage = 0
        quota_usage = my_usage + share_usage
    else:
        quota_usage = my_usage

    # Repos that are share to user
    in_repos = seafile_api.get_share_in_repo_list(email, -1, -1)

    # get user profile
    profile = Profile.objects.get_profile_by_user(email)
    d_profile = DetailedProfile.objects.get_detailed_profile_by_user(email)

    return render_to_response(
        'sysadmin/userinfo.html', {
            'owned_repos': owned_repos,
            'quota': quota,
            'quota_usage': quota_usage,
            'CALC_SHARE_USAGE': CALC_SHARE_USAGE,
            'share_usage': share_usage,
            'my_usage': my_usage,
            'in_repos': in_repos,
            'email': email,
            'profile': profile,
            'd_profile': d_profile,
            }, context_instance=RequestContext(request))

@login_required_ajax
@sys_staff_required
def user_set_quota(request, email):
    if request.method != 'POST':
        raise Http404

    content_type = 'application/json; charset=utf-8'
    result = {}

    f = SetUserQuotaForm(request.POST)
    if f.is_valid():
        email = f.cleaned_data['email']
        quota_mb = f.cleaned_data['quota']
        quota = quota_mb * (1 << 20)

        try:
            seafile_api.set_user_quota(email, quota)
        except:
            result['error'] = _(u'Failed to set quota: internal server error')
            return HttpResponse(json.dumps(result), status=500, content_type=content_type)

        result['success'] = True
        return HttpResponse(json.dumps(result), content_type=content_type)
    else:
        result['error'] = str(f.errors.values()[0])
        return HttpResponse(json.dumps(result), status=400, content_type=content_type)

@login_required
@sys_staff_required
def user_remove(request, user_id):
    """Remove user, also remove group relationship."""
    try:
        user = User.objects.get(id=int(user_id))
        user.delete()
        messages.success(request, _(u'Successfully deleted %s') % user.username)
    except User.DoesNotExist:
        messages.error(request, _(u'Failed to delete: the user does not exist'))

    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_useradmin') if referer is None else referer
        
    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def user_make_admin(request, user_id):
    """Set user as system admin."""
    try:
        user = User.objects.get(id=int(user_id))
        user.is_staff = True
        user.save()
        messages.success(request, _(u'Successfully set %s as admin') % user.username)
    except User.DoesNotExist:
        messages.error(request, _(u'Failed to set admin: the user does not exist'))

    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_useradmin') if referer is None else referer
        
    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def user_remove_admin(request, user_id):
    """Unset user admin."""
    try:
        user = User.objects.get(id=int(user_id))
        user.is_staff = False
        user.save()
        messages.success(request, _(u'Successfully revoke the admin permission of %s') % user.username)
    except User.DoesNotExist:
        messages.error(request, _(u'Failed to revoke admin: the user does not exist'))

    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_useradmin') if referer is None else referer
        
    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def user_activate(request, user_id):
    try:
        user = User.objects.get(id=int(user_id))
        user.is_active = True
        user.save()
        messages.success(request, _(u'Successfully activated "%s".') % user.email)
    except User.DoesNotExist:
        messages.success(request, _(u'Failed to activate: user does not exist.'))

    next = request.META.get('HTTP_REFERER', None)
    if not next:
        next = reverse('sys_useradmin')
        
    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def user_deactivate(request, user_id):
    try:
        user = User.objects.get(id=int(user_id))
        user.is_active = False
        user.save()
        messages.success(request, _(u'Successfully deactivated "%s".') % user.email)
    except User.DoesNotExist:
        messages.success(request, _(u'Failed to deactivate: user does not exist.'))

    next = request.META.get('HTTP_REFERER', None)
    if not next:
        next = reverse('sys_useradmin')
        
    return HttpResponseRedirect(next)

def email_user_on_activation(user):
    """Send an email to user when admin activate his/her account.
    """
    c = {
        'username': user.email,
        }
    send_html_email(_(u'Your account on %s is activated') % SITE_NAME,
            'sysadmin/user_activation_email.html', c, None, [user.email])
    
@login_required_ajax
@sys_staff_required
def user_toggle_status(request, user_id):
    content_type = 'application/json; charset=utf-8'

    try:
        user_status = int(request.GET.get('s', 0))
    except ValueError:
        user_status = 0

    try:
        user = User.objects.get(id=int(user_id))
        user.is_active = bool(user_status)
        user.save()

        if user.is_active is True:
            try:
                email_user_on_activation(user)
                email_sent = True
            except Exception as e:
                logger.error(e)
                email_sent = False

            return HttpResponse(json.dumps({'success': True,
                                            'email_sent': email_sent,
                                            }), content_type=content_type)
        return HttpResponse(json.dumps({'success': True}),
                            content_type=content_type)
    except User.DoesNotExist:
        return HttpResponse(json.dumps({'success': False}), status=500,
                            content_type=content_type)

def send_user_reset_email(request, email, password):
    """
    Send email when reset user password.
    """

    c = {
        'email': email,
        'password': password,
        }
    send_html_email(_(u'Password has been reset on %s') % SITE_NAME,
            'sysadmin/user_reset_email.html', c, None, [email])
    
@login_required
@sys_staff_required
def user_reset(request, user_id):
    """Reset password for user."""
    try:
        user = User.objects.get(id=int(user_id))
        if isinstance(INIT_PASSWD, FunctionType):
            new_password = INIT_PASSWD()
        else:
            new_password = INIT_PASSWD
        user.set_password(new_password)
        user.save()

        if IS_EMAIL_CONFIGURED:
            if SEND_EMAIL_ON_RESETTING_USER_PASSWD:
                try:
                    send_user_reset_email(request, user.email, new_password)
                    msg = _('Successfully reset password to %(passwd)s, an email has been sent to %(user)s.') % \
                        {'passwd': new_password, 'user': user.email}
                    messages.success(request, msg)
                except Exception, e:
                    logger.error(str(e))
                    msg = _('Successfully reset password to %(passwd)s, but failed to send email to %(user)s, please check your email configuration.') % \
                        {'passwd':new_password, 'user': user.email}
                    messages.success(request, msg)
            else:
                messages.success(request, _(u'Successfully reset password to %(passwd)s for user %(user)s.') % \
                                     {'passwd':new_password,'user': user.email})
        else:
            messages.success(request, _(u'Successfully reset password to %(passwd)s for user %(user)s. But email notification can not be sent, because Email service is not properly configured.') % \
                                 {'passwd':new_password,'user': user.email})
    except User.DoesNotExist:
        msg = _(u'Failed to reset password: user does not exist')
        messages.error(request, msg)

    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_useradmin') if referer is None else referer
        
    return HttpResponseRedirect(next)
    
def send_user_add_mail(request, email, password):
    """Send email when add new user."""
    c = {
        'user': request.user.username,
        'org': request.user.org,
        'email': email,
        'password': password,
        }
    send_html_email(_(u'You are invited to join %s') % SITE_NAME,
            'sysadmin/user_add_email.html', c, None, [email])

@login_required_ajax
def user_add(request):
    """Add a user"""

    if not request.user.is_staff or request.method != 'POST':
        raise Http404

    content_type = 'application/json; charset=utf-8'

    post_values = request.POST.copy()
    post_email = request.POST.get('email', '')
    post_values.update({'email': post_email.lower()})

    form = AddUserForm(post_values)
    if form.is_valid():
        email = form.cleaned_data['email']
        password = form.cleaned_data['password1']

        user = User.objects.create_user(email, password, is_staff=False,
                                        is_active=True)
        if request.user.org:
            org_id = request.user.org.org_id
            url_prefix = request.user.org.url_prefix
            ccnet_threaded_rpc.add_org_user(org_id, email, 0)
            if IS_EMAIL_CONFIGURED:
                try:
                    send_user_add_mail(request, email, password)
                    messages.success(request, _(u'Successfully added user %s. An email notification has been sent.') % email)
                except Exception, e:
                    logger.error(str(e))
                    messages.success(request, _(u'Successfully added user %s. An error accurs when sending email notification, please check your email configuration.') % email)
            else:
                messages.success(request, _(u'Successfully added user %s.') % email)

            return HttpResponse(json.dumps({'success': True}), content_type=content_type)
        else:
            if IS_EMAIL_CONFIGURED:
                if SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER:
                    try:
                        send_user_add_mail(request, email, password)
                        messages.success(request, _(u'Successfully added user %s. An email notification has been sent.') % email)
                    except Exception, e:
                        logger.error(str(e))
                        messages.success(request, _(u'Successfully added user %s. An error accurs when sending email notification, please check your email configuration.') % email)
                else:
                    messages.success(request, _(u'Successfully added user %s.') % email)
            else:
                messages.success(request, _(u'Successfully added user %s. But email notification can not be sent, because Email service is not properly configured.') % email)

            return HttpResponse(json.dumps({'success': True}), content_type=content_type)
    else:
        return HttpResponse(json.dumps({'err': str(form.errors)}), status=400, content_type=content_type)

@login_required
@sys_staff_required
def sys_group_admin(request):
    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25

    groups_plus_one = ccnet_threaded_rpc.get_all_groups(per_page * (current_page -1),
                                               per_page +1)
        
    groups = groups_plus_one[:per_page]

    if len(groups_plus_one) == per_page + 1:
        page_next = True
    else:
        page_next = False

    return render_to_response('sysadmin/sys_group_admin.html', {
            'groups': groups,
            'current_page': current_page,
            'prev_page': current_page-1,
            'next_page': current_page+1,
            'per_page': per_page,
            'page_next': page_next,
            }, context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_org_admin(request):
    orgs = ccnet_threaded_rpc.get_all_orgs(-1, -1)

    return render_to_response('sysadmin/sys_org_admin.html', {
            'orgs': orgs,
            }, context_instance=RequestContext(request))

@login_required
@sys_staff_required
def sys_org_info(request, org_id):
    org_id = int(org_id)
    org = ccnet_threaded_rpc.get_org_by_id(org_id)

    users = ccnet_threaded_rpc.get_org_emailusers(org.url_prefix, -1, -1)
    users_count = len(users)

    # quota
    total_quota = seafserv_threaded_rpc.get_org_quota(org_id)
    quota_usage = seafserv_threaded_rpc.get_org_quota_usage(org_id)
    
    # groups
    groups = ccnet_threaded_rpc.get_org_groups(org_id, -1, -1)
    groups_count = len(groups)
    
    return render_to_response('sysadmin/sys_org_info.html', {
            'org': org,
            'users': users,
            'users_count': users_count,
            'total_quota': total_quota,
            'quota_usage': quota_usage,
            'groups': groups,
            'groups_count': groups_count,
            }, context_instance=RequestContext(request))


@login_required
@sys_staff_required
def sys_publink_admin(request):
    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '100'))
    except ValueError:
        current_page = 1
        per_page = 100

    offset = per_page * (current_page -1)
    limit = per_page + 1
    publinks = FileShare.objects.all()[offset:offset+limit]

    if len(publinks) == per_page + 1:
        page_next = True
    else:
        page_next = False

    for l in publinks:
        if l.is_file_share_link():
            l.name = os.path.basename(l.path)
        else:
            l.name = os.path.dirname(l.path)

    return render_to_response(
        'sysadmin/sys_publink_admin.html', {
            'publinks': publinks,
            'current_page': current_page,
            'prev_page': current_page-1,
            'next_page': current_page+1,
            'per_page': per_page,
            'page_next': page_next,
        },
        context_instance=RequestContext(request))

@login_required
@sys_staff_required
def user_search(request):
    """Search a user.
    """
    email = request.GET.get('email', '')
    email_patt = email.replace('*', '%')
    
    users  = ccnet_threaded_rpc.search_emailusers(email_patt, -1, -1)
    last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in users])
    for user in users:
        try:
            user.self_usage = seafile_api.get_user_self_usage(user.email)
            user.share_usage = seafile_api.get_user_share_usage(user.email)
            user.quota = seafile_api.get_user_quota(user.email)
        except:
            user.self_usage = -1
            user.share_usage = -1
            user.quota = -1
        # populate user last login time
        user.last_login = None
        for last_login in last_logins:
            if last_login.username == user.email:
                user.last_login = last_login.last_login

    return render_to_response('sysadmin/user_search.html', {
            'users': users,
            'email': email,
            }, context_instance=RequestContext(request))
    
@login_required
@sys_staff_required
def sys_repo_transfer(request):
    """Transfer a repo to others.
    """
    if request.method != 'POST':
        raise Http404

    repo_id = request.POST.get('repo_id', None)
    new_owner = request.POST.get('email', None)

    if repo_id and new_owner:
        try:
            User.objects.get(email=new_owner)
            seafile_api.set_repo_owner(repo_id, new_owner)
            messages.success(request, _(u'Successfully transfered.'))    
        except User.DoesNotExist:
            messages.error(request, _(u'Failed to transfer, user %s not found') % new_owner)
    else:
        messages.error(request, _(u'Failed to transfer, invalid arguments.'))

    next = request.META.get('HTTP_REFERER', None)
    if not next:
        next = reverse(sys_repo_admin)
    return HttpResponseRedirect(next)
    
@login_required
@sys_staff_required
def sys_traffic_admin(request):
    """List all users from database.
    """
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25

    month = request.GET.get('month', '')
    if not re.match(r'[\d]{6}', month):
        month = datetime.datetime.now().strftime('%Y%m')

    start = per_page * (current_page -1)
    limit = per_page + 1
    traffic_info_list = get_user_traffic_list(month, start, limit)

    page_next = len(traffic_info_list) == limit

    for info in traffic_info_list:
        info['total'] = info['file_view'] + info['file_download'] + info['dir_download']

    return render_to_response(
        'sysadmin/sys_trafficadmin.html', {
            'traffic_info_list': traffic_info_list,
            'month': month,
            'current_page': current_page,
            'prev_page': current_page-1,
            'next_page': current_page+1,
            'per_page': per_page,
            'page_next': page_next,
        },
        context_instance=RequestContext(request))

@login_required_ajax
@sys_staff_required
def batch_user_make_admin(request):
    """Batch make users as admins.
    """
    if request.method != 'POST':
        raise Http404

    result = {}
    content_type = 'application/json; charset=utf-8'

    set_admin_emails = request.POST.get('set_admin_emails')
    set_admin_emails = string2list(set_admin_emails)

    success = []
    failed = []
    already_admin = []

    if len(get_emailusers('LDAP', 0, 1)) > 0:
        messages.error(request, _(u'Using LDAP now, can not add admin.'))
        result['success'] = True
        return HttpResponse(json.dumps(result), content_type=content_type)

    for email in set_admin_emails:
        try:
            user = User.objects.get(email=email)
            if user.is_staff is True:
                already_admin.append(email)
            else:
                user.is_staff = True
                user.save()
                success.append(email)
        except User.DoesNotExist:
            failed.append(email)

    for item in success + already_admin:
        messages.success(request, _(u'Successfully set %s as admin.') % item)
    for item in failed:
        messages.error(request, _(u'Failed to set %s as admin: user does not exist.') % item)

    result['success'] = True
    return HttpResponse(json.dumps(result), content_type=content_type)

@login_required
@sys_staff_required
def batch_add_user(request):
    """Batch add users. Import users from CSV file.
    """
    if request.method != 'POST':
        raise Http404

    form = BatchAddUserForm(request.POST, request.FILES)
    if form.is_valid():
        content = request.FILES['file'].read()
        encoding = chardet.detect(content)['encoding']
        if encoding != 'utf-8':
            content = content.decode(encoding, 'replace').encode('utf-8')

        filestream = StringIO.StringIO(content)
        reader = csv.reader(filestream)

        for row in reader:
            if not row:
                continue

            username = row[0].strip()
            password = row[1].strip()

            if not is_valid_username(username):
                continue

            if password == '':
                continue

            try:
                User.objects.get(email=username)
                continue
            except User.DoesNotExist:
                User.objects.create_user(username, password, is_staff=False,
                                         is_active=True)
        messages.success(request, _('Import succeeded'))
    else:
        messages.error(request, _(u'Please select a csv file first.'))

    next = request.META.get('HTTP_REFERER', reverse(sys_user_admin))
    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def sys_department_admin(request):
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '25'))
    except ValueError:
        current_page = 1
        per_page = 25

    offset = per_page * (current_page -1)
    limit = per_page + 1
    departments = Department.objects.all()[offset:offset+limit]

    if len(departments) == per_page + 1:
        page_next = True
    else:
        page_next = False

    return render_to_response('sysadmin/sys_department_admin.html', {
            'departments': departments,
            'current_page': current_page,
            'prev_page': current_page-1,
            'next_page': current_page+1,
            'per_page': per_page,
            'page_next': page_next,
            }, context_instance=RequestContext(request))

@login_required_ajax
@sys_staff_required
def sys_department_add(request):
    """
    Add a department.
    Only system admin can perform this operation.
    """
    if request.method != 'POST':
        raise Http404

    result = {}
    content_type = 'application/json; charset=utf-8'

    department_name = request.POST.get('department_name')

    if Department.objects.get_department_by_name(department_name) is not None:
        result['error'] = _(u'There is already a department with that name.')
        return HttpResponse(json.dumps(result), status=400,
                            content_type=content_type)

    try:
        Department.objects.add_department(department_name)
        result['success'] = True
        messages.success(request, _(u"Successfully created department."))
        return HttpResponse(json.dumps(result), content_type=content_type)
    except Exception as e:
        logger.error(e)
        messages.error(request, _(u"Failed to create department."))
        result['success'] = False
        return HttpResponse(json.dumps(result), status=500,
                            content_type=content_type)

@login_required
@sys_staff_required
def sys_department_remove(request, department_id):
    """
    Remove a department.
    Only system admin can perform this operation.
    """
    try:
        Department.objects.remove_department_by_id(department_id)
        messages.success(request, _(u"Successfully remove department."))
    except Exception as e:
        logger.error(e)
        messages.error(request, _(u"Failed to remove departmen."))

    referer = request.META.get('HTTP_REFERER', None)
    next = reverse('sys_department_admin') if referer is None else referer
    return HttpResponseRedirect(next)

@login_required
@sys_staff_required
def department_info(request, department_id):
    """
    Show base information of a department.
    """
    #users and groups in department
    department = Department.objects. \
            get_department_by_id(department_id)
    dpment_users = DepartmentUser.objects. \
            get_department_users(department_id)
    dpment_grps = DepartmentGroup.objects. \
            get_department_groups(department_id)
    user_count = DepartmentUser.objects. \
            count_department_users(department_id)
    grp_count = DepartmentGroup.objects. \
            count_department_groups(department_id)

    for dpment_grp in dpment_grps:
        group = seaserv.get_group(dpment_grp.group_id)
        if not group:
            dpment_grp.delete()
            continue
        dpment_grp.group_name = group.group_name

    #users and groups NOT in department
    #for add into department
    DB_users = get_emailusers('DB', -1, -1)
    LDAP_users = get_emailusers('LDAP', -1, -1)
    not_dpment_users = []
    all_users = []

    for DB_user in DB_users:
        all_users.append(DB_user)
    for LDAP_user in LDAP_users:
        all_users.append(LDAP_user)

    for user in all_users:
        if user.id == request.user.id:
            continue
        elif DepartmentUser.objects.get_department_user \
                    (department_id, user.email) is not None:
            continue
        else:
            not_dpment_users.append(user.email)

    all_groups = ccnet_threaded_rpc.get_all_groups(-1, -1)
    not_dpment_grps = []

    for group in all_groups:
        if DepartmentGroup.objects.get_department_group \
                    (department_id, group.id) is not None:
            continue
        else:
            not_dpment_grps.append(group)

    return render_to_response('sysadmin/department_info.html', {
            'department': department,
            'dpment_users': dpment_users,
            'dpment_grps': dpment_grps,
            'user_count': user_count,
            'grp_count': grp_count,
            'not_dpment_users': not_dpment_users,
            'not_dpment_grps': not_dpment_grps,
            }, context_instance=RequestContext(request))

@login_required_ajax
@sys_staff_required
def department_user_add(request, department_id):
    """
    Add user(s) to a department.
    """
    if request.method != 'POST':
        raise Http404

    result = {}
    content_type = 'application/json; charset=utf-8'

    if Department.objects.get_department_by_id(
                                department_id) is None:

        referer = request.META.get('HTTP_REFERER', None)
        next = reverse('department_info') if referer is None else referer
        messages.error(request, _(u"Department does not exist."))
        return HttpResponseRedirect(next)

    user_names_str = request.POST.get('added_users', '')
    user_names = string2list(user_names_str)
    user_names = [x.lower() for x in user_names]

    success = []
    exist = []
    fail = []

    for user_name in user_names:
        if not is_valid_username(user_name):
            fail.append(user_name)
            continue
        elif DepartmentUser.objects.get_department_user(department_id,
                user_name) is not None:
            exist.append(user_name)
            continue
        else:
            try:
                DepartmentUser.objects. \
                        add_department_user(department_id, user_name)
                success.append(user_name)
            except Exception as e:
                logger.error(e)

    for item in success:
        messages.success(request, _(u'Successfully add %s to department.') % item)
    for item in exist:
        messages.info(request, _(u'%s already in department.') % item)
    for item in fail:
        messages.error(request, _(u'Failed to add %s to department.') % item)

    result['success'] = True
    return HttpResponse(json.dumps(result), content_type=content_type)

@login_required
@sys_staff_required
def department_user_remove(request, department_id, user_name):
    """
    Remove a user from a department.
    """

    try:
        DepartmentUser.objects.remove_department_user(department_id, user_name)
        messages.success(request, _(u"Successful remove %s.") % user_name)
    except Exception as e:
        logger.error(e)
        messages.error(request, _(u"Failed to remove %s.") % user_name)

    next_url = reverse('department_info', args=[department_id])
    next = request.META.get('HTTP_REFERER', next_url)
    return HttpResponseRedirect(next)

@login_required_ajax
@sys_staff_required
def department_grp_add(request, department_id):
    """
    Add group(s) to a department.
    """
    if request.method != 'POST':
        raise Http404

    if Department.objects.get_department_by_id(
                                department_id) is None:

        referer = request.META.get('HTTP_REFERER', None)
        next = reverse('department_info') if referer is None else referer
        messages.error(request, _(u"Department does not exist."))
        return HttpResponseRedirect(next)

    from seahub.group.utils import get_group_dict
    group_dict = get_group_dict()

    if group_dict is None:
        referer = request.META.get('HTTP_REFERER', None)
        next = reverse('department_info') if referer is None else referer
        messages.error(request, _(u"No Group was created, please create group first."))
        return HttpResponseRedirect(next)

    result = {}
    content_type = 'application/json; charset=utf-8'

    group_names_str = request.POST.get('added_grps', '')
    group_names = string2list(group_names_str)

    success = []
    exist = []
    fail = []

    for group_name in group_names:
        if group_name in group_dict:
            group_id = group_dict[group_name]
            if DepartmentGroup.objects.get_department_group(
                            department_id, group_id) is not None:
                exist.append(group_name)
                continue
            else:
                try:
                    DepartmentGroup.objects. \
                            add_department_group(department_id, group_id)
                    success.append(group_name)
                except Exception as e:
                    logger.error(e)
        else:
            fail.append(group_name)
            continue

    for item in success + exist:
        messages.success(request, _(u'Successfully add %s to department.') % item)
    for item in fail:
        messages.error(request, _(u'Failed to add %s to department.') % item)

    result['success'] = True
    return HttpResponse(json.dumps(result), content_type=content_type)

@login_required
@sys_staff_required
def department_grp_remove(request, department_id, group_id):
    """
    Remove a group from a department.
    """
    try:
        DepartmentGroup.objects.remove_department_group(department_id, group_id)
        messages.success(request, _(u"Successful remove group."))
    except Exception as e:
        logger.error(e)
        messages.error(request, _(u"Failed to remove group."))

    next_url = reverse('department_info', args=[department_id])
    next = request.META.get('HTTP_REFERER', next_url)
    return HttpResponseRedirect(next)
