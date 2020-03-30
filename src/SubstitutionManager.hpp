/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 athre0z
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef SUBSTITUTIONMANAGER_HPP
#define SUBSTITUTIONMANAGER_HPP

#include "Utils.hpp"

#include <QDialog>
#include <regex>
#include <vector>
#include <memory>
#include <QObject>
#include <pro.h>

// ============================================================================================== //
// [Substitution]                                                                                 //
// ============================================================================================== //

struct Substitution
{
    std::string regexpPattern;
    std::regex regexp;
    std::string replacement;
};

// ============================================================================================== //
// [SubstitutionManager]                                                                          //
// ============================================================================================== //

class SubstitutionManager : public QObject, public Utils::NonCopyable
{
    Q_OBJECT

public:
    typedef std::vector<std::shared_ptr<Substitution>> SubstitutionList;
protected:
    static const std::regex m_kMarkerFinder;
    SubstitutionList m_rules;
public:
    SubstitutionManager();
    ~SubstitutionManager();
public:
    void addRule(const std::shared_ptr<Substitution> subst);
    void removeRule(const Substitution* subst);
    void clearRules();
    const SubstitutionList& rules() const { return m_rules; }
public:
    void applyToString(qstring* str) const;
signals:
    void entryAdded();
    void entryDeleted();
};

// ============================================================================================== //

#endif // SUBSTITUTIONMANAGER_HPP
