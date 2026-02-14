#! /usr/bin/env python3
'''
Copyright (c) 2012 Rowan Wookey <admin@rwky.net>
          (c) 2013 Bernd Schubert <bernd.schubert@itwm.fraunhofer.de>
          (c) 2024 Bernd Schubert <bernd@bsbernd.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import sys, subprocess, getopt, os
import re
import signal
import hashlib

gitLogCmd       = ['git', 'log', '--pretty=oneline', '--no-merges', '--no-color']
gitAuthorCmd    = ['git', 'show', '-s', '--format=(%an)', '--no-color']
gitCommitMsgCmd = ['git', 'log', '-1', '--pretty=%B', '--no-color']

branchAOnly   = False
branchBOnly   = False
reversedOrder = False
subdir = None  # New global variable to store subdirectory path
filterBySubject = False
branchAStartCommit = None  # Starting commit for branch A
branchBStartCommit = None  # Starting commit for branch B
ignorePaths = []  # List of paths to ignore

cherryPickLine = r'\(cherry picked from commit '

# just a basic commit object
class gitCommit:
    def __init__(self, commitID, commitSubject):
        self.commitID      = commitID
        self.commitSubject = commitSubject
        self.cherryPickID  = ""

    def getCommitID(self):
        return self.commitID

    def getCommitSubject(self):
        return self.commitSubject

    def addCherryPickID(self, ID):
        self.cherryPickID = ID

    def getCherryPickID(self):
        return self.cherryPickID


class Branch:
    def __init__(self, branchName):
        self.branchName = branchName
        self.patchIdDict    = {} # for fast search
        self.commitList     = []  # list of git commit ids
        self.commitObjDict  = {}  # list of gitCommit objects
        self.missingDict    = {} # list of missing commitIDs of this branch
        self.subjectHashDict = {}  # Dictionary to store subject hashes and their counts

    def hash_subject(self, subject):
        return hashlib.sha1(subject.encode()).hexdigest()

    def get_commit_message_normalized(self, commitID):
        """Get commit message with cherry-pick lines removed for comparison"""
        try:
            commitMsg = subprocess.check_output(gitCommitMsgCmd + [commitID],
                                              universal_newlines=True)
            lines = []
            for line in commitMsg.splitlines():
                if not re.search(cherryPickLine, line):
                    lines.append(line)
            return '\n'.join(lines).strip()
        except subprocess.CalledProcessError:
            return ""

    def searchCherryPickID(self, commitID):
        commitMsg = subprocess.check_output(gitCommitMsgCmd + [commitID], universal_newlines=True)

        searchRegEx  = re.compile(cherryPickLine)

        for line in commitMsg.splitlines():
            if searchRegEx.search(line):
                cherryPickID = searchRegEx.split(line)[1]

                # remove closing bracket
                cherryPickID = re.sub(r'\)$', '', cherryPickID)

                return cherryPickID

    def addCommit(self, commitID, commitSubject):
        commitObj = gitCommit(commitID, commitSubject)

        # Use errors='replace' to handle non-UTF-8 characters
        gitShow = subprocess.check_output(['git', 'show', commitID],
                                        encoding='utf-8',
                                        errors='replace')
        proc = subprocess.Popen(['git', 'patch-id'],
                              stdout=subprocess.PIPE,
                              stdin=subprocess.PIPE,
                              encoding='utf-8',
                              errors='replace')
        patchID = proc.communicate(input=gitShow)[0].split(' ')[0]

        commitObj.addCherryPickID(self.searchCherryPickID(commitID))
        # print self.branchName + ': Adding: ' + patchID + ' : ' + commitID

        self.commitList.append(commitID)
        self.commitObjDict[commitID] = commitObj
        self.patchIdDict[patchID]    = commitID

    def addLogLine(self, logLine):
        commitID      = logLine[:40]
        commitSubject = logLine[41:]
        self.addCommit(commitID, commitSubject)

    def addGitLog(self, logOutput):
        lines = logOutput.split('\n')
        if lines[-1] == '':
            lines.pop()

        for line in lines:
            self.addLogLine(line)

    def doComparedBranchLog(self, comparedBranchName, startCommit=None):
        cmd = gitLogCmd + [self.branchName]

        if 'logSinceTime' in globals():
            cmd.append('--since="%s"' % logSinceTime)
        elif startCommit:
            cmd.append('^' + startCommit)
        elif not 'exactSearch' in globals():
            cmd.append('^' + comparedBranchName)

        # Add path limitation if subdir is specified
        if 'subdir' in globals() and subdir:
            cmd.append('--')
            cmd.append(subdir)

        # print('Compared branch log: ' + str(cmd))

        log = subprocess.check_output(cmd, universal_newlines=True)
        self.addGitLog(log)

    def createMissingDict(self, comparisonDict):
        for key in comparisonDict.keys():
            if key not in self.patchIdDict:
                commitID = comparisonDict.get(key)
                self.missingDict[commitID] = commitID

                # print self.branchName + ': missing: ' + key + ' : ' + commitID

    def isCommitInMissingDict(self, commitID):
        if commitID in self.missingDict:
            return True

        return False

    # iterate over missing commits to either reverse-assign cherry-pick-ids or to
    # print missing commits
    def iterateMissingCommits(self, comparisonCommitList, comparisonCommitDict,
                            doPrint, otherBranchMissingDict=None, otherBranchCommitDict=None):

        # Note: Print in the order given by the commitList and not
        #       in arbitrary order of the commit dictionary.

        if doPrint:
            print("Missing from %s" % self.branchName)

        # Track subject occurrences during iteration
        subject_count = {}

        # Build a map of normalized messages and cherry-pick IDs from other branch's missing commits
        other_branch_msg_map = {}
        other_branch_cherry_pick_ids = {}
        if doPrint and otherBranchMissingDict and otherBranchCommitDict:
            for otherCommitID in otherBranchMissingDict.keys():
                if otherCommitID in otherBranchCommitDict:
                    msg = otherBranchCommitDict[otherCommitID].getCommitSubject()
                    normalized_msg = self.get_commit_message_normalized(otherCommitID)
                    if normalized_msg:
                        other_branch_msg_map[otherCommitID] = (msg, normalized_msg)

                    # Track cherry-pick IDs
                    cherry_pick_id = otherBranchCommitDict[otherCommitID].getCherryPickID()
                    if cherry_pick_id:
                        other_branch_cherry_pick_ids[cherry_pick_id] = otherCommitID

        for commitID in comparisonCommitList:
            if self.isCommitInMissingDict(commitID):
                cmd          = gitAuthorCmd + [commitID]
                commitAuthor = subprocess.check_output(cmd, universal_newlines=True).rstrip()
                commitObj    = comparisonCommitDict[commitID]

                cherryPickID = commitObj.getCherryPickID()
                if (cherryPickID and (cherryPickID in self.commitObjDict)):
                    # assign cherry pick id to our branch
                    if not doPrint:
                        cherryObj = self.commitObjDict[cherryPickID]
                        cherryObj.addCherryPickID(commitID)
                    continue

                if doPrint:
                    if 'filterAuthor' in globals() and \
                        not re.search(filterAuthor, commitAuthor):
                            continue # a different owner

                    # Check if commit should be ignored based on modified files
                    if should_ignore_commit(commitID):
                        continue

                    # Only calculate subject hash here for remaining commits
                    subject = commitObj.getCommitSubject()
                    subject_hash = hashlib.sha1(subject.encode()).hexdigest()

                    # Check if this commit has a matching cherry-pick ID in other branch's missing list
                    my_cherry_pick_id = commitObj.getCherryPickID()
                    if my_cherry_pick_id and my_cherry_pick_id in other_branch_cherry_pick_ids:
                        continue

                    # Check if this commit has a matching message in other branch's missing list
                    if otherBranchMissingDict and commitID in self.missingDict:
                        my_normalized_msg = self.get_commit_message_normalized(commitID)
                        if my_normalized_msg:
                            # Check if any commit in other branch's missing list has same message
                            found_match = False
                            for otherCommitID, (otherSubject, otherNormalizedMsg) in other_branch_msg_map.items():
                                if my_normalized_msg == otherNormalizedMsg and subject == otherSubject:
                                    found_match = True
                                    break
                            if found_match:
                                continue

                    # Track this subject occurrence
                    subject_count[subject_hash] = subject_count.get(subject_hash, 0) + 1

                    # Check if this subject exists in our branch
                    matching_count = len([c for c in self.commitList
                                       if self.commitObjDict[c].getCommitSubject() == subject])

                    if filterBySubject:
                        # Skip if we've seen fewer or equal occurrences in our branch
                        if subject_count[subject_hash] <= matching_count:
                            continue

                    print('  %s %s %s %s' % \
                        (('*' if matching_count > 0 else ' '),
                         commitID[:8], commitAuthor, subject))

        if doPrint:
            print()

    def printMissingCommits(self, comparisonCommitList, comparisonCommitDict,
                          otherBranchMissingDict=None, otherBranchCommitDict=None):
        self.iterateMissingCommits(comparisonCommitList, comparisonCommitDict, True,
                                  otherBranchMissingDict, otherBranchCommitDict)

    def reverseAssignCherryPickIDs(self, comparisonCommitList, comparisonCommitDict):
        self.iterateMissingCommits(comparisonCommitList, comparisonCommitDict, False, None, None)


    def getPatchIdDict(self):
        return self.patchIdDict

    def getCommitList(self):
        return self.commitList

    def getCommitObjDict(self):
        return self.commitObjDict

def usage():
        print('''
        Usage: compare-branches.py [options] <ref1> <ref2>

        Options:
          -h
                Print this help message.
          -A
                List commits missing from branch1 only.
          -B
                List commits missing from branch2 only.
          --b1 <commit>
                Starting commit for branch1 (ref1). If --b2 is not specified,
                searches backwards on branch2 to find matching commit or cherry-pick.
          --b2 <commit>
                Starting commit for branch2 (ref2). If --b1 is not specified,
                searches backwards on branch1 to find matching commit or cherry-pick.
          -d
                Print the date when the commit was created.
          -D <path>
                Only show commits that modify files under this directory path
          -e
                Exact search with *all* commits. Usually we list commits with
                'git log branch1 ^branch2', which might not be correct with
                merges between branches.
          -f
                Only print commits created by this user.
          -i <path>
                Ignore commits that only modify files under this path. Can be
                specified multiple times. Commits are shown if they modify ANY
                file outside the ignored paths.
          -r
                Print in reverse order (older (top) to newer (bottom) ).
          -S
                Filter out commits that have matching subject lines in the other branch.
          -t
                How far back in time to go (passed to git log as --since) i.e. '1 month ago'.
        ''')


def get_cherry_pick_id(commit):
    """Extract cherry-pick ID from a commit message"""
    try:
        commit_msg = subprocess.check_output(gitCommitMsgCmd + [commit],
                                            universal_newlines=True)
        searchRegEx = re.compile(cherryPickLine)
        for line in commit_msg.splitlines():
            if searchRegEx.search(line):
                cherry_pick_id = searchRegEx.split(line)[1]
                cherry_pick_id = re.sub(r'\)$', '', cherry_pick_id)
                return cherry_pick_id
    except subprocess.CalledProcessError:
        pass
    return None

def find_matching_commit_backwards(target_commit, search_branch, merge_base):
    """Search backwards on search_branch to find target_commit or its cherry-pick"""
    # Get cherry-pick ID from the target commit if it exists
    target_cherry_pick = get_cherry_pick_id(target_commit)

    cmd = ['git', 'log', '--pretty=%H', '--no-merges', '--no-color',
           search_branch, '^' + merge_base]

    try:
        log_output = subprocess.check_output(cmd, universal_newlines=True)
    except subprocess.CalledProcessError:
        return None

    commits = log_output.strip().split('\n')
    if not commits or commits[0] == '':
        return None

    for commit in commits:
        # Check if this is the exact commit hash
        if commit == target_commit:
            return commit

        # Check if this is the cherry-pick ID from target commit
        if target_cherry_pick and commit == target_cherry_pick:
            return commit

        # Check if this commit has target_commit as its cherry-pick ID
        try:
            commit_msg = subprocess.check_output(gitCommitMsgCmd + [commit],
                                                universal_newlines=True)
            if f'(cherry picked from commit {target_commit}' in commit_msg:
                return commit
            # Also check if it has the target's cherry-pick as its cherry-pick
            if target_cherry_pick and f'(cherry picked from commit {target_cherry_pick}' in commit_msg:
                return commit
        except subprocess.CalledProcessError:
            continue

    return None

def should_ignore_commit(commit_id):
    """Check if commit should be ignored based on modified files"""
    if not ignorePaths:
        return False

    try:
        # Get list of files modified in this commit
        files = subprocess.check_output(['git', 'diff-tree', '--no-commit-id',
                                        '--name-only', '-r', commit_id],
                                       universal_newlines=True)
        modified_files = files.strip().split('\n')

        # Check if any file is NOT in the ignore paths
        for file_path in modified_files:
            if not file_path:
                continue

            # Check if this file matches any ignore path
            is_ignored = False
            for ignore_path in ignorePaths:
                if file_path.startswith(ignore_path + '/') or file_path == ignore_path:
                    is_ignored = True
                    break

            # If file is not ignored, commit should be shown
            if not is_ignored:
                return False

        # All files are in ignored paths
        return True
    except subprocess.CalledProcessError:
        return False

def signal_handler(sig, frame):
    print('\nInterrupted by user. Exiting...', file=sys.stderr)
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

try:
    opts, args = getopt.getopt(sys.argv[1:], "hABdD:ef:i:rSt:", ["b1=", "b2="])
except:
    usage()
    sys.exit(1)

for opt,arg in opts:
    if opt == '-h':
        usage()
        sys.exit()
    if opt == '-A':
        branchAOnly = True
    if opt == '-B':
        branchBOnly = True
    if opt == '--b1':
        branchAStartCommit = arg
    if opt == '--b2':
        branchBStartCommit = arg
    if opt == '-d':
        # mis-use the author command and add the commit date
        gitAuthorCmd[3] = '--format=(%an) %aD'
    if opt == '-e':
        exactSearch = True
    if opt == '-f':
        filterAuthor = arg
    if opt == '-i':
        ignorePaths.append(arg.rstrip('/'))
    if opt == '-r':
        reversedOrder = True
    if opt == '-S':
        filterBySubject = True
    if opt == '-t':
        logSinceTime = arg
    if opt == '-D':
        subdir = arg.rstrip('/')  # Remove trailing slash if present
        if not os.path.exists(subdir):
            print(f"Error: Path '{subdir}' does not exist", file=sys.stderr)
            sys.exit(1)

# Check if we have exactly two branch arguments
if len(args) != 2:
    print('Error: Exactly two git references are required', file=sys.stderr)
    usage()
    sys.exit(1)

branchAName = args[0]
branchBName = args[1]

def check_ref_exists(ref_name):
    """Check if a git reference (branch/tag) exists"""
    try:
        # Use git rev-parse to check if the reference exists
        subprocess.check_output(['git', 'rev-parse', '--verify', ref_name],
                              stderr=subprocess.DEVNULL,
                              universal_newlines=True)
        return True
    except subprocess.CalledProcessError:
        print(f"Error: Branch, tag or commit '{ref_name}' does not exist", \
              file=sys.stderr)
        return False

def validate_refs(branch_a, branch_b):
    """Validate that both git references exist"""
    if not check_ref_exists(branch_a):
        sys.exit(1)

    if not check_ref_exists(branch_b):
        sys.exit(1)

validate_refs(branchAName, branchBName)

if reversedOrder:
    gitLogCmd += ['--reverse']


branchAObj = Branch(branchAName)
branchBObj = Branch(branchBName)

# Handle --b1 and --b2 options
if 'branchAStartCommit' in globals() and branchAStartCommit:
    if not ('branchBStartCommit' in globals() and branchBStartCommit):
        # Only --b1 specified, search backwards on branch B
        merge_base = subprocess.check_output(['git', 'merge-base', branchAName, branchBName],
                                            universal_newlines=True).strip()
        branchBStartCommit = find_matching_commit_backwards(branchAStartCommit, branchBName, merge_base)
        if not branchBStartCommit:
            print(f"Warning: Could not find matching commit for {branchAStartCommit} on {branchBName}",
                  file=sys.stderr)

if 'branchBStartCommit' in globals() and branchBStartCommit:
    if not ('branchAStartCommit' in globals() and branchAStartCommit):
        # Only --b2 specified, search backwards on branch A
        merge_base = subprocess.check_output(['git', 'merge-base', branchAName, branchBName],
                                            universal_newlines=True).strip()
        branchAStartCommit = find_matching_commit_backwards(branchBStartCommit, branchAName, merge_base)
        if not branchAStartCommit:
            print(f"Warning: Could not find matching commit for {branchBStartCommit} on {branchAName}",
                  file=sys.stderr)

branchAObj.doComparedBranchLog(branchBName, branchAStartCommit if 'branchAStartCommit' in globals() else None)
branchBObj.doComparedBranchLog(branchAName, branchBStartCommit if 'branchBStartCommit' in globals() else None)

branchAObj.createMissingDict(branchBObj.getPatchIdDict())
branchBObj.createMissingDict(branchAObj.getPatchIdDict())


branchAObj.reverseAssignCherryPickIDs(branchBObj.getCommitList(), \
    branchBObj.getCommitObjDict())

branchBObj.reverseAssignCherryPickIDs(branchAObj.getCommitList(), \
    branchAObj.getCommitObjDict())

if not branchBOnly:
    branchAObj.printMissingCommits(branchBObj.getCommitList(), \
        branchBObj.getCommitObjDict(), branchBObj.missingDict, branchAObj.getCommitObjDict())

if not branchAOnly:
    branchBObj.printMissingCommits(branchAObj.getCommitList(), \
        branchAObj.getCommitObjDict(), branchAObj.missingDict, branchBObj.getCommitObjDict())

#if not branchBOnly and not branchAOnly:
#    print
#    print "Commits that can be probably ignored due to merge conflicts: "
#    for msg in branch1_commit_msg:
#        if msg in branch2_commit_msg:
#            print '  ' + msg
