// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_HISTORICAL_VERIFY_H
#define BITCOIN_NODE_HISTORICAL_VERIFY_H

#include <sync.h>
#include <util/threadinterrupt.h>

#include <thread>

class ChainstateManager;

namespace node {
/**
 * Validates the assumeutxo snapshot the chainstate is based on in the
 * background, by replaying the blocks leading up to its base into a separate
 * coins database and comparing the resulting UTXO set hash to the assumeutxo
 * chainparams. See ChainstateManager::AdvanceHistoricalChain().
 */
class HistoricalReplayVerifier
{
public:
    explicit HistoricalReplayVerifier(ChainstateManager& chainman);
    ~HistoricalReplayVerifier();

    //! Start validating on a background thread, unless already started.
    void Start() EXCLUSIVE_LOCKS_REQUIRED(!m_thread_mutex);
    void Interrupt();
    //! Wait for the background thread to exit.
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_thread_mutex);

private:
    void Run();

    ChainstateManager& m_chainman;
    CThreadInterrupt m_interrupt;
    Mutex m_thread_mutex;
    std::thread m_thread GUARDED_BY(m_thread_mutex);
};
} // namespace node

#endif // BITCOIN_NODE_HISTORICAL_VERIFY_H
