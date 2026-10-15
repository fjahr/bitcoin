// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/historical_verify.h>

#include <util/thread.h>
#include <validation.h>

#include <chrono>

namespace node {
//! How long to wait before checking again whether a missing block arrived.
static constexpr auto MISSING_BLOCK_POLL_INTERVAL{std::chrono::milliseconds{100}};

HistoricalReplayVerifier::HistoricalReplayVerifier(ChainstateManager& chainman)
    : m_chainman{chainman} {}

HistoricalReplayVerifier::~HistoricalReplayVerifier()
{
    Interrupt();
    Stop();
}

void HistoricalReplayVerifier::Start()
{
    LOCK(m_thread_mutex);
    if (m_thread.joinable()) return;
    m_thread = std::thread(&util::TraceThread, "histverify", [this] { Run(); });
}

void HistoricalReplayVerifier::Interrupt()
{
    m_interrupt();
}

void HistoricalReplayVerifier::Stop()
{
    LOCK(m_thread_mutex);
    if (m_thread.joinable()) m_thread.join();
}

void HistoricalReplayVerifier::Run()
{
    using Step = ChainstateManager::HistoricalStep;
    while (!m_interrupt) {
        switch (m_chainman.AdvanceHistoricalChain()) {
        case Step::PROGRESS:
            break;
        case Step::WAITING:
            m_interrupt.sleep_for(MISSING_BLOCK_POLL_INTERVAL);
            break;
        case Step::AT_TARGET:
            m_chainman.ValidateSnapshot();
            return;
        case Step::DONE:
            return;
        } // no default case, so the compiler can warn about missing cases
    }
}
} // namespace node
